import asyncio
import logging
import json
import traceback
from datetime import datetime, timezone
from dataclasses import asdict

from app.services.scanner import ssl_check, headers_check, dns_check, port_check, breach_check, cms_check, cookie_check
from app.services.classifier import classify_findings
from app.services.ai_translator import translate_to_plain_english
from app.db.session import async_session_maker
from app.models.scan import Scan
from app.models.report import Report
from app.models.user import User
from redis.asyncio import Redis
from sqlalchemy import select

logger = logging.getLogger(__name__)

async def run_full_scan(scan_id: str, url: str, url_hash: str, redis_client: Redis):
    """
    Orchestrates the running of all 7 checks concurrently.
    """
    logger.info(f"Starting orchestration for scan_id={scan_id}, url={url}")
    start_time = datetime.now(timezone.utc)
    
    async with async_session_maker() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalars().first()
        await db.refresh(scan)

        if not scan:
            logger.error(f"Scan {scan_id} not found in DB.")
            return

        scan.status = "running"
        await db.commit()

        domain = scan.domain
        ip_address = scan.ip_address
    
    progress_key = f"scan:progress:{scan_id}"
    lock_key = f"scan:lock:{url_hash}"
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
    except Exception as e:
        logger.error(f"Redis error setting progress: {e}")

    try:
        # Check wrappers with progress updates
        async def wrap_check(name, coroutine):
            check_start = datetime.now(timezone.utc)
            try:
                progress[name] = "running"
                try:
                    await redis_client.set(progress_key, json.dumps(progress), ex=3600)
                except:
                    pass
                
                # Each explicitly wrapped in wait_for
                res = await asyncio.wait_for(coroutine, timeout=15.0)
                progress[name] = "complete"
                
                check_duration = int((datetime.now(timezone.utc) - check_start).total_seconds() * 1000)
                logger.info(f"Scan {scan_id} module {name} completed successfully in {check_duration}ms")
                
                return {"status": "success", "data": asdict(res), "error": None}
            except Exception as e:
                check_duration = int((datetime.now(timezone.utc) - check_start).total_seconds() * 1000)
                logger.error(f"Scan {scan_id} module {name} failed in {check_duration}ms: {e}", exc_info=True)
                progress[name] = "failed"
                # Graceful degradation logic
                raw_data = None
                if name == "ssl_check": raw_data = asdict(ssl_check.SSLResult(valid=False, expiry_date=None, days_until_expiry=None, tls_version=None, issuer=None, is_self_signed=False, error=str(e)))
                if name == "headers_check": raw_data = asdict(headers_check.HeadersResult(error=str(e)))
                if name == "dns_check": raw_data = asdict(dns_check.DNSResult(has_spf=False, has_dmarc=False, has_dkim=False, spf_record=None, dmarc_record=None, error=str(e)))
                if name == "port_check": raw_data = asdict(port_check.PortResult(error=str(e)))
                if name == "breach_check": raw_data = asdict(breach_check.BreachResult(error=str(e)))
                if name == "cms_check": raw_data = asdict(cms_check.CMSResult(error=str(e)))
                if name == "cookie_check": raw_data = asdict(cookie_check.CookieResult(error=str(e)))
                
                return {"status": "error", "data": raw_data, "error": str(e)}
            finally:
                try:
                    await redis_client.set(progress_key, json.dumps(progress), ex=3600)
                except:
                    pass

        # Run all concurrently
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
        
        # We must re-map raw_findings for the classifier which expects just the raw data dictionary
        classifier_data = {k: v.get("data", {}) for k, v in raw_findings.items()}

        # Classify
        classified = classify_findings(classifier_data)
        
        # AI Translation
        ai_items = await translate_to_plain_english(classified, domain)
        
        # Format explicitly into dict for JSONB
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
                        await redis_client.set(cache_key, scan.id, ex=21600)  # 6 hours
                    except Exception as e:
                        logger.error(f"Redis cache error: {e}")
                        
                logger.info(f"Scan {scan_id} completed in {duration_ms}ms with status={scan.status}")

    except Exception as e:
        logger.error(f"Scan {scan_id} failed catastrophically: {e}", exc_info=True)
        async with async_session_maker() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalars().first()
            if scan:
                scan.status = "failed"
                scan.error_message = str(e)
                await db.commit()
    finally:
        # Delete the idempotency lock
        try:
            await redis_client.delete(lock_key)
        except Exception as e:
            logger.error(f"Failed to release lock {lock_key}: {e}")