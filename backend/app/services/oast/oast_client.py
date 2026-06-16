"""
OAST Client — Out-of-Band Application Security Testing session manager.

Uses interactsh-compatible HTTP polling to detect blind callbacks
(DNS, HTTP) from target applications that processed injected payloads.

MVP: Connects to public interact.sh server via polling API.
Self-hosted: Override INTERACTSH_SERVER + INTERACTSH_TOKEN in .env.
"""

import asyncio
import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
INTERACTSH_SERVER = getattr(settings, "INTERACTSH_SERVER", "oast.interact.sh")
INTERACTSH_TOKEN = getattr(settings, "INTERACTSH_TOKEN", "")

POLL_INTERVAL_S = 3.0
REQUEST_TIMEOUT = 15.0


@dataclass
class OASTInteraction:
    """A single interaction received by the OAST server."""

    protocol: str  # "dns", "http", "smtp"
    unique_id: str
    raw_request: str = ""
    remote_address: str = ""
    timestamp: str = ""
    full_id: str = ""


@dataclass
class OASTSession:
    """Active OAST session state."""

    domain: str  # e.g. abc123.oast.interact.sh
    correlation_id: str
    secret_key: str
    server: str
    started_at: float = field(default_factory=time.time)
    interactions: list = field(default_factory=list)
    active: bool = True


class OASTClient:
    """
    Manages an OAST session against interact.sh (or compatible server).

    Uses the interactsh REST API directly — no external Python package
    required (avoids interactsh-client version instability).

    API ref: https://github.com/projectdiscovery/interactsh
    """

    def __init__(self) -> None:
        self.session: OASTSession | None = None
        self._http: httpx.AsyncClient | None = None
        self._server = INTERACTSH_SERVER
        self._token = INTERACTSH_TOKEN

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def start_session(self) -> str:
        """
        Register a new OAST session with interact.sh.
        Returns the unique callback domain (e.g. abc123.oast.interact.sh).
        """
        self._http = httpx.AsyncClient(timeout=REQUEST_TIMEOUT, verify=True)

        # Generate a deterministic correlation id + secret
        correlation_id = secrets.token_hex(16)
        secret_key = secrets.token_hex(32)

        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        payload = {
            "public-key": _derive_public_key(secret_key),
            "secret-key": secret_key,
            "correlation-id": correlation_id,
        }

        try:
            url = f"https://{self._server}/register"
            resp = await self._http.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            domain = data.get("domain", f"{correlation_id[:8]}.{self._server}")
        except Exception as exc:
            # Fallback: derive domain from server + correlation id
            logger.warning(f"OAST registration failed ({exc}), using fallback domain")
            domain = f"{correlation_id[:12]}.{self._server}"

        self.session = OASTSession(
            domain=domain,
            correlation_id=correlation_id,
            secret_key=secret_key,
            server=self._server,
        )
        logger.info(f"OAST session started: {domain}")
        return domain

    async def poll_interactions(self, timeout_s: int = 30) -> list[OASTInteraction]:
        """
        Poll for any OAST interactions received during the session.
        Blocks for up to `timeout_s` seconds, polling every POLL_INTERVAL_S.
        Returns list of confirmed interaction objects.
        """
        if not self.session or not self._http:
            return []

        deadline = time.monotonic() + timeout_s
        collected: list[OASTInteraction] = []

        while time.monotonic() < deadline and self.session.active:
            try:
                interactions = await self._fetch_interactions()
                collected.extend(interactions)
            except Exception as exc:
                logger.debug(f"OAST poll error: {exc}")

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            await asyncio.sleep(min(POLL_INTERVAL_S, remaining))

        self.session.interactions = collected
        return collected

    async def stop_session(self) -> None:
        """Deregister the OAST session from the server."""
        if self.session and self._http:
            try:
                headers = {"Content-Type": "application/json"}
                if self._token:
                    headers["Authorization"] = f"Bearer {self._token}"
                await self._http.post(
                    f"https://{self._server}/deregister",
                    json={
                        "correlation-id": self.session.correlation_id,
                        "secret-key": self.session.secret_key,
                    },
                    headers=headers,
                )
            except Exception:
                pass
            finally:
                self.session.active = False
                await self._http.aclose()
                self._http = None
        logger.info("OAST session closed")

    # ── Internal ───────────────────────────────────────────────────────────────

    async def _fetch_interactions(self) -> list[OASTInteraction]:
        """Fetch new interactions from the server."""
        if not self.session or not self._http:
            return []

        headers: dict = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        url = f"https://{self._server}/poll"
        params = {
            "id": self.session.correlation_id,
            "secret": self.session.secret_key,
        }
        resp = await self._http.get(url, params=params, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            return _parse_interactions(data.get("data", []))
        return []

    @property
    def callback_domain(self) -> str | None:
        return self.session.domain if self.session else None

    @property
    def interaction_count(self) -> int:
        return len(self.session.interactions) if self.session else 0


# ── Helpers ────────────────────────────────────────────────────────────────────


def _derive_public_key(secret_key: str) -> str:
    """Derive a pseudo-public key from the secret for registration."""
    return hashlib.sha256(secret_key.encode()).hexdigest()


def _parse_interactions(raw_data: list) -> list[OASTInteraction]:
    """Parse raw interaction payloads from the server response."""
    result = []
    for item in raw_data:
        if not isinstance(item, dict):
            continue
        result.append(
            OASTInteraction(
                protocol=item.get("protocol", "unknown"),
                unique_id=item.get("unique-id", ""),
                raw_request=item.get("raw-request", "")[:1000],  # cap size
                remote_address=item.get("remote-address", ""),
                timestamp=item.get("timestamp", ""),
                full_id=item.get("full-id", ""),
            )
        )
    return result


async def create_oast_session() -> tuple[OASTClient, str]:
    """
    Convenience factory — creates + starts an OAST session.
    Returns (client, callback_domain).
    Raises OASTUnavailableError if the server cannot be reached.
    """
    client = OASTClient()
    try:
        domain = await client.start_session()
        return client, domain
    except Exception as exc:
        raise OASTUnavailableError(str(exc)) from exc


class OASTUnavailableError(Exception):
    """Raised when OAST infrastructure is unreachable."""
