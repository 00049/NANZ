from fastapi import APIRouter, HTTPException, Query, Request

from app.main import limiter
from app.services.scanner.dns_check import run as run_dns_check
from app.services.scanner.headers_check import run as run_headers_check
from app.utils.url_validator import validate_scan_url

router = APIRouter(tags=["Tools"])


@router.get("/headers")
@limiter.limit("20/minute")
async def check_headers(request: Request, url: str = Query(..., min_length=4)) -> dict:
    """Standalone endpoint for HTTP Security Headers check."""
    is_valid, resolved_ip_or_error = validate_scan_url(url)
    if not is_valid:
        status_code = (
            422
            if "http://" in resolved_ip_or_error or "https://" in resolved_ip_or_error
            else 400
        )
        raise HTTPException(status_code=status_code, detail=resolved_ip_or_error)

    try:
        raw_result = await run_headers_check(url)

        headers_list = []
        for d in raw_result.header_details:
            status_map = {
                "pass": "present",
                "missing": "missing",
                "warning": "misconfigured",
                "fail": "missing",
            }

            headers_list.append(
                {
                    "name": d["name"],
                    "value": d["value"],
                    "status": status_map.get(d["status"], "missing"),
                    "description": d.get("detail", ""),
                    "fix": (
                        f"Configure {d['name']} correctly on your web server."
                        if d["status"] != "pass"
                        else ""
                    ),
                }
            )

        return {"grade": raw_result.grade, "headers": headers_list}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/email")
@limiter.limit("20/minute")
async def check_email(request: Request, domain: str = Query(..., min_length=3)) -> dict:
    """Standalone endpoint for Email Security Check (SPF, DMARC, DKIM, MX, BIMI)."""
    check_domain = domain[4:] if domain.lower().startswith("www.") else domain

    try:
        dns_res = await run_dns_check(check_domain)
        dns_dict = dns_res.__dict__

        # Calculate overall score similarly to email_security_check
        score = 100
        if not dns_dict.get("has_spf"):
            score -= 20
        elif dns_dict.get("spf_all_mechanism") == "+all":
            score -= 30
        if not dns_dict.get("has_dmarc"):
            score -= 20
        elif dns_dict.get("dmarc_not_enforced"):
            score -= 10
        if not dns_dict.get("has_dkim"):
            score -= 10
        if not dns_dict.get("has_mx"):
            score -= 10
        if not dns_dict.get("has_bimi"):
            score -= 5
        score = max(0, min(100, score))

        records = []

        # SPF
        records.append(
            {
                "type": "SPF",
                "value": dns_dict.get("spf_record", "Missing"),
                "status": "present" if dns_dict.get("has_spf") else "missing",
                "risk": (
                    "Critical for preventing email spoofing."
                    if not dns_dict.get("has_spf")
                    else (
                        "SPF mechanism is weak."
                        if dns_dict.get("spf_all_mechanism") == "+all"
                        else "Good."
                    )
                ),
                "fix": (
                    "Add a TXT record for SPF."
                    if not dns_dict.get("has_spf")
                    else (
                        "Change +all to ~all or -all."
                        if dns_dict.get("spf_all_mechanism") == "+all"
                        else ""
                    )
                ),
            }
        )

        # DMARC
        records.append(
            {
                "type": "DMARC",
                "value": dns_dict.get("dmarc_record", "Missing"),
                "status": "present" if dns_dict.get("has_dmarc") else "missing",
                "risk": (
                    "Essential for email authentication alignment."
                    if not dns_dict.get("has_dmarc")
                    else (
                        "Policy is not enforced (p=none)."
                        if dns_dict.get("dmarc_not_enforced")
                        else "Good."
                    )
                ),
                "fix": (
                    "Add a _dmarc TXT record."
                    if not dns_dict.get("has_dmarc")
                    else (
                        "Enforce policy to quarantine or reject."
                        if dns_dict.get("dmarc_not_enforced")
                        else ""
                    )
                ),
            }
        )

        # DKIM
        dkim_found = dns_dict.get("has_dkim", False)
        records.append(
            {
                "type": "DKIM",
                "value": (
                    f"Found selectors: {', '.join(dns_dict.get('dkim_selectors_found', []))}"
                    if dkim_found
                    else "Missing"
                ),
                "status": "present" if dkim_found else "missing",
                "risk": (
                    "Cryptographic proof of email origin."
                    if not dkim_found
                    else "Good."
                ),
                "fix": (
                    "Configure DKIM signing in your email provider."
                    if not dkim_found
                    else ""
                ),
            }
        )

        # MX
        mx_found = dns_dict.get("has_mx", False)
        mx_records = dns_dict.get("mx_records", [])
        mx_value = (
            ", ".join([m["server"] for m in mx_records]) if mx_records else "Missing"
        )
        records.append(
            {
                "type": "MX",
                "value": mx_value,
                "status": "present" if mx_found else "missing",
                "risk": "Required to receive emails." if not mx_found else "Good.",
                "fix": (
                    "Add MX records pointing to your mail server."
                    if not mx_found
                    else ""
                ),
            }
        )

        # BIMI
        bimi_found = dns_dict.get("has_bimi", False)
        records.append(
            {
                "type": "BIMI",
                "value": dns_dict.get("bimi_record", "Missing"),
                "status": "present" if bimi_found else "missing",
                "risk": (
                    "Improves brand visibility in inboxes."
                    if not bimi_found
                    else "Good."
                ),
                "fix": (
                    "Publish a BIMI record with your verified logo."
                    if not bimi_found
                    else ""
                ),
            }
        )

        return {"overall_score": score, "records": records}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
