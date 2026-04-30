"""
Email Security Deep Analysis.

Consolidates SPF, DMARC, DKIM, MX, BIMI, and MTA-STS into a single 0-100 score.
"""

import logging
from dataclasses import dataclass
from typing import Optional

from app.services.scanner.dns_check import run as run_dns_check

logger = logging.getLogger(__name__)

@dataclass
class EmailSecurityResult:
    score: int
    grade: str
    spf_status: str
    dmarc_status: str
    dkim_found: bool
    bimi_found: bool
    mta_sts_found: bool
    mx_starttls_supported: bool
    details: dict
    error: Optional[str] = None

def _calculate_score(result: dict) -> tuple[int, str]:
    score = 100
    
    # Base protections (heavy weight)
    if not result.get("has_spf"):
        score -= 20
    elif result.get("spf_all_mechanism") == "+all":
        score -= 30
        
    if not result.get("has_dmarc"):
        score -= 20
    elif result.get("dmarc_not_enforced"):
        score -= 10
        
    if not result.get("has_dkim"):
        score -= 10
        
    if not result.get("has_mx"):
        score -= 10
        
    # Advanced protections
    if not result.get("has_bimi"):
        score -= 5
    if not result.get("has_mta_sts"):
        score -= 5
    if result.get("smtp_no_starttls"):
        score -= 20
        
    # Boundary checks
    score = max(0, min(100, score))
    
    # Letter grade
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
        
    return score, grade

async def run(domain: str) -> EmailSecurityResult:
    """Run full email security analysis."""
    dns_result = await run_dns_check(domain)
    # Convert dataclass to dict
    dns_dict = dns_result.__dict__
    
    score, grade = _calculate_score(dns_dict)
    
    spf_status = "Missing"
    if dns_dict.get("has_spf"):
        mech = dns_dict.get("spf_all_mechanism", "~all")
        spf_status = f"Valid ({mech})"
        
    dmarc_status = "Missing"
    if dns_dict.get("has_dmarc"):
        pol = dns_dict.get("dmarc_policy", "none")
        dmarc_status = f"Active (p={pol})"
        
    return EmailSecurityResult(
        score=score,
        grade=grade,
        spf_status=spf_status,
        dmarc_status=dmarc_status,
        dkim_found=dns_dict.get("has_dkim", False),
        bimi_found=dns_dict.get("has_bimi", False),
        mta_sts_found=dns_dict.get("has_mta_sts", False),
        mx_starttls_supported=not dns_dict.get("smtp_no_starttls", False),
        details=dns_dict
    )
