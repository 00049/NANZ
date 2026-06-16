import asyncio
import uuid
from app.db.session import async_session_maker
from app.models.scan import Scan
from app.models.report import Report
from sqlalchemy import select

async def main():
    scan_id = uuid.uuid4()
    async with async_session_maker() as db:
        scan = Scan(id=scan_id, url="https://example.com", domain="example.com", status="queued")
        db.add(scan)
        await db.commit()

        # Try to insert Report like in orchestrator.py when all_failed=True
        report = Report(
            scan_id=scan.id,
            overall_severity="CRITICAL",
            overall_score=0,
            risk_items=[],
            ai_summary="Scan failed. Detailed AI analysis is currently unavailable.",
            executive_summary="Scan failed.",
            checks_run={"checks": [], "total": 27},
            domain_reports={"enterprise": {}},
            ssl_score=0,
            header_score=0,
            total_findings=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            info_count=0,
            dpdp_compliance_score=0,
            dpdp_issues=[],
            waf_detected=False,
            waf_provider=None,
            javascript_findings=None,
            cors_findings=None,
            cloud_findings=None,
            email_findings=None,
            performance_findings=None,
            tech_findings=None,
            crawl_findings=None,
            compliance_report=None,
            brand_threats=None,
            bola_findings=None,
            api_findings=None,
            llm_findings=None,
            oast_interactions=None,
            cve_findings=None,
            owasp_coverage=None,
            owasp_llm_coverage=None,
            compliance_report_v2=None,
            dpdp_penalty_crore=None,
            ale_reduction_total=None,
            kev_findings_count=0,
            severity_adjusted_count=0,
        )
        db.add(report)
        try:
            await db.commit()
            print("Successfully inserted Report!")
        except Exception as e:
            print(f"Failed to insert Report: {e}")

if __name__ == "__main__":
    asyncio.run(main())
