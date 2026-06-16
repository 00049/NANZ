"""
CISA KEV Client — Known Exploited Vulnerabilities catalog.

Downloads and caches the full CISA KEV catalog from:
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

The catalog is stored in Redis as a JSON-serialized set of CVE IDs with a 1-hour TTL.
On cache miss, the catalog is fetched and re-populated.

Usage:
    from app.services.threat_intel.kev_client import is_in_kev, get_kev_entry

    if await is_in_kev("CVE-2021-44228"):
        # This CVE is in the CISA Known Exploited Vulnerabilities catalog

No API key required. Free public feed.
"""

import json
import logging

import httpx

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_REDIS_KEY = "cisa_kev_catalog"
_REDIS_ENTRY_KEY = "cisa_kev_entries"  # Full entry data for enrichment
_REDIS_TTL = 3600  # 1 hour


async def _get_redis():
    """Lazily import redis to avoid hard dependency at module load time."""
    try:
        from redis.asyncio import Redis

        from app.config import settings

        r = Redis.from_url(
            settings.REDIS_URL, decode_responses=True, socket_connect_timeout=2
        )
        return r
    except Exception:
        return None


async def _fetch_kev_catalog() -> dict:
    """
    Fetch the full CISA KEV catalog from the public feed.

    Returns:
        {"cve_ids": set[str], "entries": dict[str, dict]}
    """
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()

        vulnerabilities = data.get("vulnerabilities", [])
        cve_ids = set()
        entries: dict[str, dict] = {}

        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID", "").upper()
            if cve_id:
                cve_ids.add(cve_id)
                entries[cve_id] = {
                    "vendor_project": vuln.get("vendorProject", ""),
                    "product": vuln.get("product", ""),
                    "vulnerability_name": vuln.get("vulnerabilityName", ""),
                    "date_added": vuln.get("dateAdded", ""),
                    "short_description": vuln.get("shortDescription", ""),
                    "required_action": vuln.get("requiredAction", ""),
                    "due_date": vuln.get("dueDate", ""),
                    "known_ransomware": vuln.get(
                        "knownRansomwareCampaignUse", "Unknown"
                    )
                    == "Known",
                }

        logger.info(f"CISA KEV catalog fetched: {len(cve_ids)} CVEs")
        return {"cve_ids": cve_ids, "entries": entries}

    except httpx.TimeoutException:
        logger.warning("CISA KEV fetch timed out")
        return {"cve_ids": set(), "entries": {}}
    except Exception as exc:
        logger.warning(f"CISA KEV fetch failed: {exc}")
        return {"cve_ids": set(), "entries": {}}


async def _load_catalog() -> tuple[set[str], dict]:
    """
    Load KEV catalog from Redis cache or fetch fresh.

    Returns: (cve_id_set, entries_dict)
    """
    redis = await _get_redis()
    if redis:
        try:
            cached_ids = await redis.get(_REDIS_KEY)
            cached_entries = await redis.get(_REDIS_ENTRY_KEY)
            if cached_ids and cached_entries:
                cve_ids = set(json.loads(cached_ids))
                entries = json.loads(cached_entries)
                return cve_ids, entries
        except Exception as exc:
            logger.debug(f"KEV Redis cache miss: {exc}")
        finally:
            try:
                await redis.aclose()
            except Exception:
                pass

    # Fetch fresh catalog
    catalog = await _fetch_kev_catalog()
    cve_ids = catalog["cve_ids"]
    entries = catalog["entries"]

    # Cache in Redis
    if cve_ids and redis:
        try:
            r2 = await _get_redis()
            if r2:
                await r2.set(_REDIS_KEY, json.dumps(list(cve_ids)), ex=_REDIS_TTL)
                await r2.set(_REDIS_ENTRY_KEY, json.dumps(entries), ex=_REDIS_TTL)
                await r2.aclose()
        except Exception as exc:
            logger.debug(f"KEV Redis cache write failed: {exc}")

    return cve_ids, entries


async def is_in_kev(cve_id: str) -> bool:
    """
    Check if a CVE ID is in the CISA Known Exploited Vulnerabilities catalog.

    Args:
        cve_id: CVE identifier string (e.g. "CVE-2021-44228")

    Returns:
        True if in KEV catalog, False otherwise
    """
    if not cve_id:
        return False

    cve_id = cve_id.upper().strip()
    try:
        cve_ids, _ = await _load_catalog()
        return cve_id in cve_ids
    except Exception as exc:
        logger.warning(f"KEV lookup failed for {cve_id}: {exc}")
        return False


async def get_kev_entry(cve_id: str) -> dict | None:
    """
    Get the full KEV entry for a CVE ID.

    Returns dict with vendor_project, product, vulnerability_name,
    date_added, short_description, required_action, due_date,
    known_ransomware keys — or None if not in catalog.
    """
    if not cve_id:
        return None

    cve_id = cve_id.upper().strip()
    try:
        cve_ids, entries = await _load_catalog()
        if cve_id in cve_ids:
            return entries.get(cve_id)
        return None
    except Exception as exc:
        logger.warning(f"KEV entry lookup failed for {cve_id}: {exc}")
        return None


async def get_kev_batch(cve_ids: list[str]) -> dict[str, bool]:
    """
    Check multiple CVE IDs against the KEV catalog in one call.

    Returns dict: {"CVE-2021-44228": True, "CVE-2020-0000": False, ...}
    """
    if not cve_ids:
        return {}

    try:
        catalog_ids, _ = await _load_catalog()
        return {cve_id.upper(): cve_id.upper() in catalog_ids for cve_id in cve_ids}
    except Exception as exc:
        logger.warning(f"KEV batch lookup failed: {exc}")
        return {cve_id: False for cve_id in cve_ids}


async def get_catalog_stats() -> dict:
    """Return basic stats about the cached KEV catalog."""
    try:
        cve_ids, entries = await _load_catalog()
        ransomware_count = sum(1 for e in entries.values() if e.get("known_ransomware"))
        return {
            "total_cves": len(cve_ids),
            "ransomware_associated": ransomware_count,
            "catalog_source": "CISA KEV",
        }
    except Exception:
        return {
            "total_cves": 0,
            "ransomware_associated": 0,
            "catalog_source": "CISA KEV",
        }
