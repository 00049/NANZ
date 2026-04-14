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
from redis.asyncio import Redis
from sqlalchemy import select

logger = logging.getLogger(__name__)

async def run_full_scan(scan_id: str, url: str, redis_client: Redis):
    """
    Orchestrates the running of all 7 checks concurrently.
    """
    start_time = datetime.now(timezone.utc)
    
    async with async_session_maker() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalars().first()
        if not scan:
            logger.error(f"Scan {scan_id} not found in DB.")
            return

        scan.status = "running"
        await db.commit()
    
    progress_key = f"scan:progress:{scan_id}"
    progress = {
        "ssl_check": "pending",
        "headers_check": "pending",
        "dns_check": "pending",
        "port_check": "pending",
        "breach_check": "pending",
        "cms_check": "pending",
        "cookie_check": "pending"
    }
    await redis_client.set(progress_key, json.dumps(progress), ex=3600)

    try:
        domain = scan.domain
        ip_address = scan.ip_address

        # Check wrappers with progress updates
        async def wrap_check(name, coroutine):
            try:
                progress[name] = "running"
                await redis_client.set(progress_key, json.dumps(progress), ex=3600)
                
                # Each explicitly wrapped in wait_for
                res = await asyncio.wait_for(coroutine, timeout=10.0)
                progress[name] = "complete"
                return res
            except Exception as e:
                logger.error(f"Scan {scan_id} check {name} failed: {e}", exc_info=True)
                progress[name] = "failed"
                # Return default objects based on name to avoid failing entire orchestrator
                if name == "ssl_check": return ssl_check.SSLResult(valid=False, expiry_date=None, days_until_expiry=None, tls_version=None, issuer=None, is_self_signed=False, error=str(e))
                if name == "headers_check": return headers_check.HeadersResult(error=str(e))
                if name == "dns_check": return dns_check.DNSResult(has_spf=False, has_dmarc=False, has_dkim=False, spf_record=None, dmarc_record=None, error=str(e))
                if name == "port_check": return port_check.PortResult(error=str(e))
                if name == "breach_check": return breach_check.BreachResult(error=str(e))
                if name == "cms_check": return cms_check.CMSResult(error=str(e))
                if name == "cookie_check": return cookie_check.CookieResult(error=str(e))
            finally:
                await redis_client.set(progress_key, json.dumps(progress), ex=3600)

        # Run all concurrently
        results = await asyncio.gather(
            wrap_check("ssl_check", ssl_check.run(domain)),
            wrap_check("headers_check", headers_check.run(url)),
            wrap_check("dns_check", dns_check.run(domain)),
            wrap_check("port_check", port_check.run(ip_address, redis_client)),
            wrap_check("breach_check", breach_check.run(domain)),
            wrap_check("cms_check", cms_check.run(url)),
            wrap_check("cookie_check", cookie_check.run(url)),
            return_exceptions=True
        )

        raw_findings = {
            "ssl": asdict(results[0]) if not isinstance(results[0], Exception) else {},
            "headers": asdict(results[1]) if not isinstance(results[1], Exception) else {},
            "dns": asdict(results[2]) if not isinstance(results[2], Exception) else {},
            "ports": asdict(results[3]) if not isinstance(results[3], Exception) else {},
            "breach": asdict(results[4]) if not isinstance(results[4], Exception) else {},
            "cms": asdict(results[5]) if not isinstance(results[5], Exception) else {},
            "cookies": asdict(results[6]) if not isinstance(results[6], Exception) else {}
        }

        # Classify
        classified = classify_findings(raw_findings)
        
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
                scan.status = "complete"
                scan.completed_at = end_time
                
                report = Report(
                    scan_id=scan.id,
                    overall_severity=overall_severity,
                    risk_items=ai_items_dict,
                    checks_run={"checks": list(raw_findings.keys())},
                    ssl_score=0, # Could be calculated later
                    header_score=raw_findings.get("headers", {}).get("score", 0)
                )
                db.add(report)
                await db.commit()

    except Exception as e:
        logger.error(f"Scan {scan_id} failed catastrophically: {e}", exc_info=True)
        async with async_session_maker() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalars().first()
            if scan:
                scan.status = "failed"
                scan.error_message = str(e)
                await db.commit()
