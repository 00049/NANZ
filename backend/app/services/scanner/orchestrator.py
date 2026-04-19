import asyncio
import hashlib
import logging
import json
from datetime import datetime, timezone
from dataclasses import asdict

from app.services.scanner import ssl_check, headers_check, dns_check, port_check, breach_check, cms_check, cookie_check
from app.services.classifier import classify_findings
from app.services.ai_translator import translate_to_plain_english
from app.db.session import async_session_maker
from app.models import Report, Scan
from app.config import settings
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)


def _json_safe(value: object) -> object:
    """Convert dataclass output into JSON-compatible values."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


async def run_full_scan(scan_id: str, url: str, redis_client: Redis) -> None:
    """
    Orchestrates the running of all 7 checks concurrently.
    """
    logger.info(f"Starting orchestration for scan_id={scan_id}, url={url}")
    start_time = datetime.now(timezone.utc)
    
    try:
        async with async_session_maker() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalars().first()

            if not scan:
                logger.error(f"Scan {scan_id} not found in DB.")
                return

            await db.refresh(scan)
            scan.status = "running"
            await db.commit()

            domain = scan.domain
            ip_address = scan.ip_address
    except SQLAlchemyError as e:
        logger.error(f"Database error preparing scan_id={scan_id}: {e}", exc_info=True)
        return
    
    progress_key = f"scan:progress:{scan_id}"
    url_hash = hashlib.sha256(url.lower().strip().encode("utf-8")).hexdigest()
    cache_key = f"scan:url:{url_hash}"

    progress = {
        "ssl_check": "pending",
        "headers_check": "pending",
        "dns_check": "pending",
        "port_check": "pending",
        "breach_check": "pending",
        "cms_check": "pending",
        "cookie_check": "pending"
    }
    
    try:
        await redis_client.set(progress_key, json.dumps(progress), ex=3600)
    except (ConnectionError, TimeoutError, OSError, ValueError) as e:
        logger.error(f"Redis error setting scan_id={scan_id} progress: {e}", exc_info=True)

    try:
        async def wrap_check(name: str, coroutine: asyncio.Future) -> dict:
            """Run a scanner coroutine with timeout, progress, and safe fallback data."""
            check_start = datetime.now(timezone.utc)
            try:
                progress[name] = "running"
                try:
                    await redis_client.set(progress_key, json.dumps(progress), ex=3600)
                except (ConnectionError, TimeoutError, OSError, ValueError) as e:
                    logger.error(f"Redis error marking scan_id={scan_id} check={name} running: {e}", exc_info=True)
                
                res = await asyncio.wait_for(coroutine, timeout=10.0)
                progress[name] = "complete"
                
                check_duration = int((datetime.now(timezone.utc) - check_start).total_seconds() * 1000)
                logger.info(f"Scan {scan_id} module {name} completed successfully in {check_duration}ms")
                
                return {"status": "success", "data": _json_safe(asdict(res)), "error": None}
            except Exception as e:
                check_duration = int((datetime.now(timezone.utc) - check_start).total_seconds() * 1000)
                logger.error(f"Scan {scan_id} module {name} failed in {check_duration}ms: {e}", exc_info=True)
                progress[name] = "failed"
                raw_data = None
                if name == "ssl_check":
                    raw_data = asdict(ssl_check.SSLResult(valid=False, expiry_date=None, days_until_expiry=None, tls_version=None, issuer=None, is_self_signed=False, error="SSL check unavailable"))
                if name == "headers_check":
                    raw_data = asdict(headers_check.HeadersResult(error="Header check unavailable"))
                if name == "dns_check":
                    raw_data = asdict(dns_check.DNSResult(has_spf=False, has_dmarc=False, has_dkim=False, spf_record=None, dmarc_record=None, error="DNS check unavailable"))
                if name == "port_check":
                    raw_data = asdict(port_check.PortResult(error="Port check unavailable"))
                if name == "breach_check":
                    raw_data = asdict(breach_check.BreachResult(error="Breach check unavailable"))
                if name == "cms_check":
                    raw_data = asdict(cms_check.CMSResult(error="CMS check unavailable"))
                if name == "cookie_check":
                    raw_data = asdict(cookie_check.CookieResult(error="Cookie check unavailable"))

                return {"status": "error", "data": raw_data, "error": "Check failed"}
            finally:
                try:
                    await redis_client.set(progress_key, json.dumps(progress), ex=3600)
                except (ConnectionError, TimeoutError, OSError, ValueError) as e:
                    logger.error(f"Redis error updating scan_id={scan_id} check={name}: {e}", exc_info=True)

        results = await asyncio.gather(
            wrap_check("ssl_check", ssl_check.run(domain)),
            wrap_check("headers_check", headers_check.run(url)),
            wrap_check("dns_check", dns_check.run(domain)),
            wrap_check("port_check", port_check.run(ip_address or "", redis_client)),
            wrap_check("breach_check", breach_check.run(domain)),
            wrap_check("cms_check", cms_check.run(url)),
            wrap_check("cookie_check", cookie_check.run(url)),
            return_exceptions=True
        )

        raw_findings = {
            "ssl": results[0] if not isinstance(results[0], Exception) else {"status": "error", "error": "Fatal Error"},
            "headers": results[1] if not isinstance(results[1], Exception) else {"status": "error", "error": "Fatal Error"},
            "dns": results[2] if not isinstance(results[2], Exception) else {"status": "error", "error": "Fatal Error"},
            "ports": results[3] if not isinstance(results[3], Exception) else {"status": "error", "error": "Fatal Error"},
            "breach": results[4] if not isinstance(results[4], Exception) else {"status": "error", "error": "Fatal Error"},
            "cms": results[5] if not isinstance(results[5], Exception) else {"status": "error", "error": "Fatal Error"},
            "cookies": results[6] if not isinstance(results[6], Exception) else {"status": "error", "error": "Fatal Error"}
        }
        
        all_failed = all(res.get("status") == "error" for _, res in raw_findings.items() if isinstance(res, dict))
        
        classifier_data = {k: v.get("data", {}) for k, v in raw_findings.items()}

        classified = classify_findings(classifier_data)
        ai_items = await translate_to_plain_english(classified, domain)
        ai_items_dict = [item.model_dump() for item in ai_items]
        
        overall_severity = "GREEN"
        if any(item.severity == "RED" for item in ai_items):
            overall_severity = "RED"
        elif any(item.severity == "AMBER" for item in ai_items):
            overall_severity = "AMBER"

        end_time = datetime.now(timezone.utc)
        duration_ms = int((end_time - start_time).total_seconds() * 1000)

        async with async_session_maker() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalars().first()
            if scan:
                scan.raw_findings = raw_findings
                scan.scan_duration_ms = duration_ms
                
                if all_failed:
                    scan.status = "failed"
                    scan.error_message = "All scanning checks failed."
                else:
                    scan.status = "complete"
                    
                scan.completed_at = end_time
                
                if not all_failed:
                    report = Report(
                        scan_id=scan.id,
                        overall_severity=overall_severity,
                        risk_items=ai_items_dict,
                        checks_run={"checks": list(raw_findings.keys())},
                        ssl_score=0,
                        header_score=classifier_data.get("headers", {}).get("score", 0) if isinstance(classifier_data.get("headers"), dict) else 0
                    )
                    db.add(report)
                    
                await db.commit()
                
                # Cache successful/partial successful scan
                if not all_failed:
                    try:
                        await redis_client.set(cache_key, str(scan.id), ex=settings.SCAN_CACHE_HOURS * 3600)
                    except (ConnectionError, TimeoutError, OSError, ValueError) as e:
                        logger.error(f"Redis cache error for scan_id={scan_id}: {e}", exc_info=True)
                        
                logger.info(f"Scan {scan_id} completed in {duration_ms}ms with status={scan.status}")

    except Exception as e:
        logger.error(f"Scan {scan_id} failed catastrophically: {e}", exc_info=True)
        async with async_session_maker() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalars().first()
            if scan:
                scan.status = "failed"
                scan.error_message = "Scan processing failed"
                await db.commit()
    finally:
        try:
            await redis_client.expire(progress_key, 3600)
        except (ConnectionError, TimeoutError, OSError, ValueError) as e:
            logger.error(f"Failed to set scan_id={scan_id} progress TTL: {e}", exc_info=True)
