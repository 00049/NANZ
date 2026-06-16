"""
Brand Monitor — Module 5: CT Log & Brand Protection

Detects lookalike domains threatening your brand via three tiers:
  Tier 1 — Levenshtein typosquatting
  Tier 2 — Unicode homoglyph spoofing (Cyrillic/Greek substitutions)
  Tier 3 — Real-time Certificate Transparency log monitoring (crt.sh)
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Unicode homoglyph table — common lookalike character substitutions
# ---------------------------------------------------------------------------

HOMOGLYPH_TABLE: dict[str, list[str]] = {
    "a": ["а", "à", "á", "â", "ã", "ä", "å", "α"],  # Cyrillic а, Greek α
    "b": ["Ь", "ḃ", "ƅ"],
    "c": ["с", "ċ", "ć", "č"],  # Cyrillic с
    "d": ["ԁ", "ḋ", "ḑ"],
    "e": ["е", "ė", "ê", "ë", "é", "è", "ε"],  # Cyrillic е, Greek ε
    "g": ["ġ", "ģ"],
    "h": ["հ", "ḥ"],
    "i": ["і", "í", "ì", "î", "ï", "ı", "ι"],  # Cyrillic і, Greek ι
    "j": ["ϳ", "ĵ"],
    "k": ["κ", "ķ"],  # Greek κ
    "l": ["ӏ", "ĺ", "ł", "ļ"],  # Cyrillic ӏ
    "m": ["м", "ṁ"],  # Cyrillic м
    "n": ["ñ", "ń", "ṅ", "η"],  # Greek η
    "o": ["о", "ο", "ô", "ó", "ò", "ö", "ø", "σ"],  # Cyrillic о, Greek ο
    "p": ["р", "ρ"],  # Cyrillic р, Greek ρ
    "q": ["ԛ"],
    "r": ["г", "ṙ"],  # Cyrillic г
    "s": ["ѕ", "ś", "ṡ"],  # Cyrillic ѕ
    "t": ["τ", "ţ"],  # Greek τ
    "u": ["υ", "ü", "ú", "ù", "û"],  # Greek υ
    "v": ["ν", "ṿ"],  # Greek ν
    "w": ["ω", "ẇ"],  # Greek ω
    "x": ["х", "χ"],  # Cyrillic х, Greek χ
    "y": ["у", "γ", "ý", "ÿ"],  # Cyrillic у, Greek γ
    "z": ["ź", "ż", "ẑ"],
    "0": ["о", "О"],
    "1": ["l", "I", "і"],
    "3": ["е"],
    "5": ["ѕ"],
}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class BrandThreat:
    threat_type: str  # "typosquat" | "homoglyph" | "ct_alert"
    domain: str  # The suspicious domain
    similarity_score: float  # 0.0–1.0
    is_live: bool  # Whether domain resolves
    cert_issued_at: str | None = None
    issuing_ca: str | None = None
    ip_address: str | None = None
    threat_level: str = "MEDIUM"  # CRITICAL / HIGH / MEDIUM / LOW


@dataclass
class BrandThreatResult:
    domain: str
    threats: list[BrandThreat] = field(default_factory=list)
    typosquats_checked: int = 0
    homoglyphs_checked: int = 0
    ct_certs_checked: int = 0
    error: str | None = None


# ---------------------------------------------------------------------------
# Levenshtein distance (Tier 1 — typosquatting)
# ---------------------------------------------------------------------------


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1, 1):
        new_row = [i]
        for j, c2 in enumerate(s2, 1):
            new_row.append(min(row[j] + 1, new_row[-1] + 1, row[j - 1] + (c1 != c2)))
        row = new_row
    return row[-1]


def _generate_typosquats(name: str) -> list[str]:
    """Generate common typosquat variants: character omission, swap, double, substitution."""
    variants: set[str] = set()
    n = len(name)

    # Character deletion
    for i in range(n):
        variants.add(name[:i] + name[i + 1 :])

    # Character transposition
    for i in range(n - 1):
        swapped = list(name)
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        variants.add("".join(swapped))

    # Character insertion (adjacent keyboard keys — simplified)
    kbd = {
        "a": "sq",
        "e": "rw",
        "i": "ou",
        "o": "ip",
        "u": "yi",
        "s": "ad",
        "n": "mb",
        "t": "yr",
        "r": "et",
        "l": "k",
    }
    for i, ch in enumerate(name):
        for nb in kbd.get(ch, ""):
            variants.add(name[:i] + nb + name[i:])

    # Common brand suffix/prefix attacks
    variants.add(name + "s")
    variants.add(name + "-secure")
    variants.add(name + "-login")
    variants.add("my" + name)
    variants.add(name + "app")

    # Discard the original and very short variants
    variants.discard(name)
    return [v for v in variants if len(v) >= 3]


# ---------------------------------------------------------------------------
# Homoglyph generator (Tier 2)
# ---------------------------------------------------------------------------


def generate_homoglyphs(name: str, max_variants: int = 50) -> list[str]:
    """
    Generate Unicode homoglyph variants of a domain name (SLD part only).
    Each generated string swaps at most one or two characters.
    """
    variants: set[str] = set()

    for i, ch in enumerate(name.lower()):
        subs = HOMOGLYPH_TABLE.get(ch, [])
        for s in subs:
            variants.add(name[:i] + s + name[i + 1 :])
            # Double substitution (slightly slower but catches combos)
            for j, ch2 in enumerate(name.lower()):
                if j != i:
                    for s2 in HOMOGLYPH_TABLE.get(ch2, []):
                        v = name[:i] + s + name[i + 1 :]
                        v = v[:j] + s2 + v[j + 1 :]
                        variants.add(v)
                        if len(variants) >= max_variants:
                            break

    variants.discard(name)
    return list(variants)[:max_variants]


# ---------------------------------------------------------------------------
# Certificate Transparency monitor (Tier 3 — crt.sh)
# ---------------------------------------------------------------------------


async def _query_ct_logs(client: httpx.AsyncClient, domain: str) -> list[dict]:
    """Query crt.sh for recently issued certificates similar to the target domain."""
    try:
        # Query crt.sh for the exact domain and all subdomains
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = await client.get(url, timeout=15.0)
        if resp.status_code != 200:
            return []
        certs = resp.json()
        if not isinstance(certs, list):
            return []
        return certs[:200]  # cap results
    except Exception as e:
        logger.warning(f"CT log query failed for {domain}: {e}")
        return []


def _parse_cert_domain(name_value: str) -> list[str]:
    """Extract individual domains from a certificate's common name or SAN."""
    parts = re.split(r"[\n,]", name_value)
    return [p.strip().lstrip("*.") for p in parts if p.strip()]


# ---------------------------------------------------------------------------
# Live domain resolution check
# ---------------------------------------------------------------------------


async def _is_domain_live(
    client: httpx.AsyncClient, fqdn: str
) -> tuple[bool, str | None]:
    """Return (is_live, ip_address) by making a HEAD request."""
    for scheme in ("https://", "http://"):
        try:
            await client.head(
                f"{scheme}{fqdn}", timeout=5.0, follow_redirects=True
            )
            return True, None  # IP extraction would require DNS lookup
        except Exception:
            pass
    return False, None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def check_brand_threats(domain: str) -> dict:
    """
    Run all three tiers of brand protection checks against a domain.
    Returns a serializable dict.
    """
    # Extract SLD (e.g., "bennett" from "bennett.edu.in")
    parts = domain.split(".")
    if len(parts) >= 2:
        sld = parts[-2]  # second-level domain
        tld = "." + ".".join(parts[-1:]) if len(parts) >= 3 else f".{parts[-1]}"
    else:
        sld = domain
        tld = ".com"

    result = BrandThreatResult(domain=domain)
    threats: list[BrandThreat] = []

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:

        # ── Tier 1: Typosquatting ──────────────────────────────────────────
        typosquats = _generate_typosquats(sld)
        result.typosquats_checked = len(typosquats)

        # Check top 20 typosquats for liveness (to stay fast)
        for variant in typosquats[:20]:
            fqdn = f"{variant}{tld}"
            sim = 1.0 - (_levenshtein(sld, variant) / max(len(sld), len(variant)))
            if sim < 0.7:
                continue
            is_live, ip = await _is_domain_live(client, fqdn)
            if is_live:
                threats.append(
                    BrandThreat(
                        threat_type="typosquat",
                        domain=fqdn,
                        similarity_score=round(sim, 3),
                        is_live=True,
                        ip_address=ip,
                        threat_level="HIGH" if sim > 0.85 else "MEDIUM",
                    )
                )

        # ── Tier 2: Homoglyph spoofing ────────────────────────────────────
        homoglyphs = generate_homoglyphs(sld, max_variants=30)
        result.homoglyphs_checked = len(homoglyphs)

        for variant in homoglyphs[:15]:
            fqdn = f"{variant}{tld}"
            is_live, ip = await _is_domain_live(client, fqdn)
            # Homoglyphs that resolve are immediately HIGH/CRITICAL (active phishing infra)
            if is_live:
                threats.append(
                    BrandThreat(
                        threat_type="homoglyph",
                        domain=fqdn,
                        similarity_score=0.95,  # visually identical
                        is_live=True,
                        ip_address=ip,
                        threat_level="CRITICAL",
                    )
                )

        # ── Tier 3: CT Log monitoring ─────────────────────────────────────
        certs = await _query_ct_logs(client, domain)
        result.ct_certs_checked = len(certs)

        seen_ct: set[str] = set()
        for cert in certs:
            name_value = cert.get("name_value", "")
            cert_domains = _parse_cert_domain(name_value)
            issued_at = cert.get("entry_timestamp", "")
            ca_name = cert.get("issuer_name", "Unknown CA")
            cert.get("id", "")

            for cert_domain in cert_domains:
                if cert_domain == domain or cert_domain in seen_ct:
                    continue
                # Only flag if similar to the target SLD
                cert_sld = (
                    cert_domain.split(".")[0] if "." in cert_domain else cert_domain
                )
                dist = _levenshtein(sld, cert_sld)
                sim = 1.0 - (dist / max(len(sld), len(cert_sld), 1))
                if sim >= 0.75 and cert_domain != domain:
                    seen_ct.add(cert_domain)
                    threats.append(
                        BrandThreat(
                            threat_type="ct_alert",
                            domain=cert_domain,
                            similarity_score=round(sim, 3),
                            is_live=False,  # CT alert — not yet verified live
                            cert_issued_at=issued_at,
                            issuing_ca=ca_name,
                            threat_level="HIGH" if sim > 0.9 else "MEDIUM",
                        )
                    )

    result.threats = threats

    # Serialize to dict
    return {
        "domain": domain,
        "total_threats": len(threats),
        "critical_threats": sum(1 for t in threats if t.threat_level == "CRITICAL"),
        "high_threats": sum(1 for t in threats if t.threat_level == "HIGH"),
        "medium_threats": sum(1 for t in threats if t.threat_level == "MEDIUM"),
        "typosquats_checked": result.typosquats_checked,
        "homoglyphs_checked": result.homoglyphs_checked,
        "ct_certs_checked": result.ct_certs_checked,
        "threats": [asdict(t) for t in threats],
    }
