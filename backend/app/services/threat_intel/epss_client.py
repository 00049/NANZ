"""
EPSS Client — Exploit Prediction Scoring System (FIRST.org).

Fetches EPSS scores for CVE IDs from the free FIRST.org API.
Scores indicate the probability that a CVE will be exploited in the wild
within 30 days (0.0 = very unlikely, 1.0 = near-certain exploitation).

API: https://api.first.org/data/v1/epss?cve={cve_id}
No API key required. Results cached in Redis for 24 hours.

Usage:
    from app.services.threat_intel.epss_client import get_epss, get_epss_batch

    data = await get_epss("CVE-2021-44228")
    # {"epss_score": 0.975, "epss_percentile": 99}

    batch = await get_epss_batch(["CVE-2021-44228", "CVE-2022-22965"])
    # {"CVE-2021-44228": {"epss_score": 0.975, ...}, ...}
"""

import json
import logging

import httpx

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
_REDIS_TTL = 86400  # 24 hours


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


async def get_epss(cve_id: str) -> dict:
    """
    Fetch EPSS score for a single CVE ID.

    Returns dict with keys:
        epss_score: float (0.0–1.0)
        epss_percentile: int (0–100)
        error: str | None
    """
    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return {"epss_score": None, "epss_percentile": None, "error": "Invalid CVE ID"}

    cve_id = cve_id.upper()
    cache_key = f"epss:{cve_id}"

    # ── Check Redis cache ──
    redis = await _get_redis()
    if redis:
        try:
            cached = await redis.get(cache_key)
            if cached:
                return json.loads(cached)
        except Exception as exc:
            logger.debug(f"EPSS Redis cache miss for {cve_id}: {exc}")
        finally:
            try:
                await redis.aclose()
            except Exception:
                pass

    # ── Fetch from FIRST.org ──
    result = {"epss_score": None, "epss_percentile": None, "error": None}
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(EPSS_API_URL, params={"cve": cve_id})
            resp.raise_for_status()
            data = resp.json()
            items = data.get("data", [])
            if items:
                item = items[0]
                epss_score = float(item.get("epss", 0.0))
                percentile_raw = item.get("percentile", 0.0)
                epss_percentile = int(float(percentile_raw) * 100)
                result = {
                    "epss_score": round(epss_score, 4),
                    "epss_percentile": epss_percentile,
                    "error": None,
                }
            else:
                result["error"] = "CVE not found in EPSS database"
    except httpx.TimeoutException:
        result["error"] = "EPSS API timeout"
    except httpx.HTTPStatusError as exc:
        result["error"] = f"EPSS API HTTP {exc.response.status_code}"
    except Exception as exc:
        logger.warning(f"EPSS fetch failed for {cve_id}: {exc}")
        result["error"] = str(exc)[:100]

    # ── Cache the result ──
    if redis and result.get("epss_score") is not None:
        try:
            r2 = await _get_redis()
            if r2:
                await r2.set(cache_key, json.dumps(result), ex=_REDIS_TTL)
                await r2.aclose()
        except Exception:
            pass

    return result


async def get_epss_batch(cve_ids: list[str]) -> dict[str, dict]:
    """
    Fetch EPSS scores for up to 100 CVE IDs in a single API request.

    Returns dict keyed by CVE ID:
        {"CVE-2021-44228": {"epss_score": 0.975, "epss_percentile": 99, "error": None}, ...}
    """
    if not cve_ids:
        return {}

    cve_ids = [c.upper() for c in cve_ids if c and c.upper().startswith("CVE-")]
    if not cve_ids:
        return {}

    # Limit to 100 per API docs
    cve_ids = cve_ids[:100]
    results: dict[str, dict] = {}

    # ── Check Redis cache for each ID ──
    redis = await _get_redis()
    uncached: list[str] = []

    if redis:
        try:
            for cve_id in cve_ids:
                cached = await redis.get(f"epss:{cve_id}")
                if cached:
                    results[cve_id] = json.loads(cached)
                else:
                    uncached.append(cve_id)
        except Exception:
            uncached = list(cve_ids)
        finally:
            try:
                await redis.aclose()
            except Exception:
                pass
    else:
        uncached = list(cve_ids)

    if not uncached:
        return results

    # ── Batch fetch for uncached IDs ──
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(EPSS_API_URL, params={"cve": ",".join(uncached)})
            resp.raise_for_status()
            data = resp.json()
            items = data.get("data", [])

            fetched_ids = set()
            for item in items:
                cve_id = item.get("cve", "").upper()
                if not cve_id:
                    continue
                fetched_ids.add(cve_id)
                epss_score = round(float(item.get("epss", 0.0)), 4)
                percentile_raw = item.get("percentile", 0.0)
                epss_percentile = int(float(percentile_raw) * 100)
                results[cve_id] = {
                    "epss_score": epss_score,
                    "epss_percentile": epss_percentile,
                    "error": None,
                }

            # Fill in not-found CVEs
            for cve_id in uncached:
                if cve_id not in fetched_ids:
                    results[cve_id] = {
                        "epss_score": None,
                        "epss_percentile": None,
                        "error": "CVE not in EPSS database",
                    }

    except Exception as exc:
        logger.warning(f"EPSS batch fetch failed: {exc}")
        for cve_id in uncached:
            results.setdefault(
                cve_id,
                {
                    "epss_score": None,
                    "epss_percentile": None,
                    "error": str(exc)[:100],
                },
            )

    # ── Cache successful results ──
    if redis:
        try:
            r2 = await _get_redis()
            if r2:
                for cve_id, result in results.items():
                    if result.get("epss_score") is not None:
                        await r2.set(
                            f"epss:{cve_id}", json.dumps(result), ex=_REDIS_TTL
                        )
                await r2.aclose()
        except Exception:
            pass

    return results


def classify_epss(epss_score: float | None) -> str:
    """
    Convert an EPSS score into a human-readable exploitation likelihood label.

    Returns: "Critical" | "High" | "Medium" | "Low" | "Unknown"
    """
    if epss_score is None:
        return "Unknown"
    if epss_score >= 0.5:
        return "Critical"
    if epss_score >= 0.3:
        return "High"
    if epss_score >= 0.1:
        return "Medium"
    return "Low"
