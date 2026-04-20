"""
Expanded Classifier — now with CRITICAL severity level.

Evaluates raw scan findings from all 8 domains against hard-coded security
rules. Returns ALL findings sorted by severity (CRITICAL → RED → AMBER → GREEN → INFO).
No longer limited to top 3 — that's handled by the free/paid gate in the API.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Severity sort order
SEVERITY_ORDER = {"CRITICAL": 0, "RED": 1, "AMBER": 2, "GREEN": 3, "INFO": 4}


def classify_findings(raw: dict) -> list[dict]:
    """
    Evaluate raw scan findings against hard-coded security rules.
    Returns ALL findings sorted by severity.

    CRITICAL triggers: exposed DB ports, .env/.git exposed, zone transfer,
    malware/phishing detection, exposed databases with no auth.
    """
    findings: list[dict] = []

    _classify_ssl(raw.get("ssl") or {}, findings)
    _classify_headers(raw.get("headers") or {}, findings)
    _classify_dns(raw.get("dns") or {}, findings)
    _classify_ports(raw.get("ports") or {}, findings)
    _classify_breach(raw.get("breach") or {}, findings)
    _classify_cms(raw.get("cms") or {}, findings)
    _classify_cookies(raw.get("cookies") or {}, findings)
    _classify_webapp(raw.get("webapp") or {}, findings)
    _classify_reputation(raw.get("reputation") or {}, findings)
    _classify_infra(raw.get("infra") or {}, findings)

    # Sort: CRITICAL → RED → AMBER → GREEN → INFO
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 5))

    return findings


def _add(findings: list, check: str, severity: str, key: str, data: dict, **extra: Any) -> None:
    """Helper to append a finding."""
    finding = {"check": check, "severity": severity, "key": key, "data": data}
    finding.update(extra)
    findings.append(finding)


# ──────────────────────────────────────────────────
# Domain 1: SSL/TLS
# ──────────────────────────────────────────────────
def _classify_ssl(ssl: dict, findings: list) -> None:
    if not ssl:
        return

    # CRITICAL: Heartbleed or ROBOT
    if ssl.get("heartbleed_vulnerable"):
        _add(findings, "ssl", "CRITICAL", "ssl_heartbleed", ssl)
    if ssl.get("robot_vulnerable"):
        _add(findings, "ssl", "CRITICAL", "ssl_robot", ssl)

    # RED: invalid cert
    if not ssl.get("valid") and not ssl.get("error"):
        _add(findings, "ssl", "RED", "ssl_invalid", ssl)
    elif ssl.get("error"):
        _add(findings, "ssl", "RED", "ssl_unavailable", ssl)

    # RED: self-signed
    if ssl.get("is_self_signed"):
        _add(findings, "ssl", "RED", "ssl_self_signed", ssl)

    # RED: TLS 1.0 or 1.1 supported
    if ssl.get("supports_tls_1_0"):
        _add(findings, "ssl", "RED", "ssl_tls10_supported", ssl)
    if ssl.get("supports_tls_1_1"):
        _add(findings, "ssl", "RED", "ssl_tls11_supported", ssl)

    # RED: weak ciphers
    if ssl.get("has_null_cipher"):
        _add(findings, "ssl", "RED", "ssl_null_cipher", ssl)
    if ssl.get("has_rc4_cipher"):
        _add(findings, "ssl", "RED", "ssl_rc4_cipher", ssl)
    if ssl.get("has_des_cipher"):
        _add(findings, "ssl", "RED", "ssl_des_cipher", ssl)
    if ssl.get("has_export_cipher"):
        _add(findings, "ssl", "RED", "ssl_export_cipher", ssl)

    # RED: expiry < 14 days
    days = ssl.get("days_until_expiry", 999)
    if isinstance(days, (int, float)) and days < 14:
        _add(findings, "ssl", "RED", "ssl_expiring_critical", ssl)
    elif isinstance(days, (int, float)) and days <= 30:
        _add(findings, "ssl", "AMBER", "ssl_expiring_soon", ssl)

    # AMBER: no TLS 1.3
    if ssl.get("supports_tls_1_2") and not ssl.get("supports_tls_1_3"):
        _add(findings, "ssl", "AMBER", "ssl_no_tls13", ssl)

    # AMBER: no CT logs
    if ssl.get("valid") and not ssl.get("has_ct_logs"):
        _add(findings, "ssl", "AMBER", "ssl_no_ct_logs", ssl)

    # AMBER: no OCSP stapling
    if ssl.get("valid") and not ssl.get("has_ocsp_stapling"):
        _add(findings, "ssl", "AMBER", "ssl_no_ocsp", ssl)

    # AMBER: wildcard cert
    if ssl.get("is_wildcard"):
        _add(findings, "ssl", "AMBER", "ssl_wildcard_cert", ssl)

    # AMBER: old TLS version in use
    if ssl.get("tls_version") in ("TLSv1", "TLSv1.1"):
        _add(findings, "ssl", "RED", "ssl_old_tls", ssl)


# ──────────────────────────────────────────────────
# Domain 2: HTTP Headers
# ──────────────────────────────────────────────────
def _classify_headers(headers: dict, findings: list) -> None:
    if not headers:
        return

    missing = headers.get("missing", [])
    if len(missing) >= 4:
        _add(findings, "headers", "RED", "headers_many_missing", headers)
    elif len(missing) >= 2:
        _add(findings, "headers", "AMBER", "headers_some_missing", headers)
    elif len(missing) == 1:
        _add(findings, "headers", "GREEN", "headers_one_missing", headers)

    # Server exposes version
    if headers.get("server_exposes_version"):
        _add(findings, "headers", "AMBER", "headers_server_version_exposed", headers)

    # X-Powered-By present
    if headers.get("xpowered_exposes_tech"):
        _add(findings, "headers", "AMBER", "headers_tech_stack_exposed", headers)

    # Unsafe referrer policy
    if headers.get("referrer_unsafe"):
        _add(findings, "headers", "RED", "headers_unsafe_referrer", headers)

    # Redirect issues
    redirect_info = headers.get("redirect_info") or {}
    if not redirect_info.get("http_to_https"):
        _add(findings, "headers", "RED", "headers_no_https_redirect", headers)
    if redirect_info.get("too_many_redirects"):
        _add(findings, "headers", "AMBER", "headers_too_many_redirects", headers)

    # HSTS issues
    hsts_max = headers.get("hsts_max_age")
    if hsts_max is not None and hsts_max < 31536000:
        _add(findings, "headers", "AMBER", "headers_hsts_short_max_age", headers)

    # CSP report-only
    if headers.get("csp_report_only"):
        _add(findings, "headers", "AMBER", "headers_csp_report_only", headers)


# ──────────────────────────────────────────────────
# Domain 3: DNS
# ──────────────────────────────────────────────────
def _classify_dns(dns_data: dict, findings: list) -> None:
    if not dns_data:
        return

    # CRITICAL: Zone transfer
    if dns_data.get("zone_transfer_possible"):
        _add(findings, "dns", "CRITICAL", "dns_zone_transfer", dns_data)

    # RED: +all in SPF (anyone can send)
    if dns_data.get("spf_all_mechanism") == "+all":
        _add(findings, "dns", "RED", "dns_spf_plus_all", dns_data)

    has_spf = dns_data.get("has_spf", False)
    has_dmarc = dns_data.get("has_dmarc", False)

    if not has_spf and not has_dmarc:
        _add(findings, "dns", "RED", "dns_no_email_protection", dns_data)
    elif not has_spf:
        _add(findings, "dns", "AMBER", "dns_no_spf", dns_data)
    elif not has_dmarc:
        _add(findings, "dns", "AMBER", "dns_no_dmarc", dns_data)

    # AMBER: DMARC not enforced
    if dns_data.get("dmarc_not_enforced"):
        _add(findings, "dns", "AMBER", "dns_dmarc_not_enforced", dns_data)

    # AMBER: SPF too many lookups
    if dns_data.get("spf_too_many_lookups"):
        _add(findings, "dns", "AMBER", "dns_spf_too_many_lookups", dns_data)

    # AMBER: No DNSSEC
    if not dns_data.get("has_dnssec"):
        _add(findings, "dns", "AMBER", "dns_no_dnssec", dns_data)

    # AMBER: No CAA
    if not dns_data.get("has_caa"):
        _add(findings, "dns", "AMBER", "dns_no_caa", dns_data)

    # GREEN: No DKIM
    if not dns_data.get("has_dkim"):
        _add(findings, "dns", "GREEN", "dns_no_dkim", dns_data)

    # INFO: Resolved subdomains
    subs = dns_data.get("discovered_subdomains", [])
    if subs:
        _add(findings, "dns", "INFO", "dns_subdomains_found", dns_data,
             detail=f"{len(subs)} common subdomains resolve")


# ──────────────────────────────────────────────────
# Domain 4: Ports
# ──────────────────────────────────────────────────
def _classify_ports(ports: dict, findings: list) -> None:
    if not ports:
        return

    open_ports = ports.get("open_ports", [])
    critical_exposed = ports.get("critical_ports_exposed", [])
    dangerous_exposed = ports.get("dangerous_ports_exposed", [])

    # CRITICAL: database ports exposed
    db_ports = {3306, 5432, 27017, 6379, 9200}
    exposed_db = [p for p in open_ports if p in db_ports]
    if exposed_db:
        _add(findings, "ports", "CRITICAL", "ports_database_exposed", ports,
             detail=f"Database ports exposed: {exposed_db}")

    # RED: FTP (21), Telnet (23), RDP (3389), VNC (5900)
    red_ports = {21, 23, 3389, 5900, 445}
    exposed_red = [p for p in open_ports if p in red_ports]
    if exposed_red:
        _add(findings, "ports", "RED", "dangerous_ports_exposed", ports,
             detail=f"Dangerous ports: {exposed_red}")

    # AMBER: non-standard web ports
    amber_ports = {8080, 8443, 8888}
    exposed_amber = [p for p in open_ports if p in amber_ports]
    if exposed_amber:
        _add(findings, "ports", "AMBER", "unusual_ports_open", ports,
             detail=f"Non-standard web ports: {exposed_amber}")


# ──────────────────────────────────────────────────
# Domain 5: Breach (kept from original)
# ──────────────────────────────────────────────────
def _classify_breach(breach: dict, findings: list) -> None:
    if not breach:
        return

    if breach.get("breached"):
        count = breach.get("breach_count", 0)
        _add(findings, "breach", "RED", "domain_in_breach", breach,
             detail=f"Found in {count} known data breaches")


# ──────────────────────────────────────────────────
# Domain 6: CMS
# ──────────────────────────────────────────────────
def _classify_cms(cms: dict, findings: list) -> None:
    if not cms:
        return

    # RED: Exposed API keys in source
    exposed_keys = cms.get("exposed_api_keys", [])
    if exposed_keys:
        _add(findings, "cms", "CRITICAL", "cms_api_keys_exposed", cms,
             detail=f"Exposed keys: {', '.join(exposed_keys)}")

    # RED: Admin panel exposed
    if cms.get("admin_exposed"):
        _add(findings, "cms", "RED", "cms_admin_exposed", cms)

    # RED: Installation files left behind
    install_files = cms.get("install_files_exposed", [])
    if install_files:
        _add(findings, "cms", "RED", "cms_install_files_exposed", cms,
             detail=f"Installation files found: {', '.join(install_files)}")

    # AMBER: Outdated CMS version
    if cms.get("outdated_version"):
        _add(findings, "cms", "AMBER", "cms_outdated", cms)

    # WordPress-specific
    wp_vuln_plugins = cms.get("wp_vulnerable_plugins", 0)
    if wp_vuln_plugins > 0:
        _add(findings, "cms", "RED", "cms_wp_vulnerable_plugins", cms,
             detail=f"{wp_vuln_plugins} vulnerable WordPress plugins")

    wp_core_vulns = cms.get("wp_core_vulnerabilities", [])
    if wp_core_vulns:
        _add(findings, "cms", "RED", "cms_wp_core_vulnerable", cms,
             detail=f"{len(wp_core_vulns)} WordPress core vulnerabilities")

    # AMBER: WordPress users enumerable
    wp_users = cms.get("wp_users_found", [])
    if wp_users:
        _add(findings, "cms", "AMBER", "cms_wp_users_enumerated", cms,
             detail=f"Users found: {', '.join(wp_users[:3])}")

    # AMBER: WordPress readme exposed
    if cms.get("wp_readme_exposed"):
        _add(findings, "cms", "AMBER", "cms_wp_readme_exposed", cms)


# ──────────────────────────────────────────────────
# Domain 7: Cookies (kept from original)
# ──────────────────────────────────────────────────
def _classify_cookies(cookies: dict, findings: list) -> None:
    if not cookies:
        return

    if cookies.get("session_cookies_insecure"):
        _add(findings, "cookies", "RED", "session_cookie_insecure", cookies)
    elif not cookies.get("all_have_samesite", True):
        _add(findings, "cookies", "AMBER", "cookie_missing_samesite", cookies)


# ──────────────────────────────────────────────────
# Domain 8: Web Application
# ──────────────────────────────────────────────────
def _classify_webapp(webapp: dict, findings: list) -> None:
    if not webapp:
        return

    # CRITICAL: Exposed sensitive files
    exposed_files = webapp.get("exposed_files", [])
    for ef in exposed_files:
        severity = ef.get("severity", "RED")
        path = ef.get("path", "")
        if severity == "CRITICAL":
            _add(findings, "webapp", "CRITICAL", f"webapp_exposed_{path.replace('/', '_').strip('_')}", webapp,
                 detail=ef.get("description", "Sensitive file exposed"))
        else:
            _add(findings, "webapp", severity, f"webapp_exposed_{path.replace('/', '_').strip('_')}", webapp,
                 detail=ef.get("description", "File exposed"))

    # Nuclei findings
    nuclei_findings = webapp.get("nuclei_findings", [])
    for nf in nuclei_findings:
        severity = nf.get("severity", "INFO")
        if severity in ("CRITICAL", "RED", "AMBER"):
            _add(findings, "webapp", severity, f"webapp_nuclei_{nf.get('template_id', 'unknown')}", webapp,
                 detail=nf.get("name", ""))

    # Mozilla Observatory grade
    obs = webapp.get("observatory") or {}
    grade = obs.get("grade")
    if grade and grade.startswith("F"):
        _add(findings, "webapp", "RED", "webapp_observatory_grade_f", webapp,
             detail=f"Mozilla Observatory grade: {grade}")
    elif grade and grade.startswith("D"):
        _add(findings, "webapp", "AMBER", "webapp_observatory_grade_d", webapp,
             detail=f"Mozilla Observatory grade: {grade}")

    # GREEN: security.txt present
    if webapp.get("has_security_txt"):
        _add(findings, "webapp", "GREEN", "webapp_security_txt_present", webapp)


# ──────────────────────────────────────────────────
# Domain 9: Reputation
# ──────────────────────────────────────────────────
def _classify_reputation(rep: dict, findings: list) -> None:
    if not rep:
        return

    # Google Safe Browsing — malware/phishing
    gsb = rep.get("safe_browsing") or {}
    if gsb.get("checked") and not gsb.get("is_safe"):
        threats = gsb.get("threats_found", [])
        _add(findings, "reputation", "CRITICAL", "rep_google_unsafe", rep,
             detail=f"Google Safe Browsing threats: {', '.join(threats)}")

    # VirusTotal — malicious detections
    vt = rep.get("virustotal") or {}
    if vt.get("checked"):
        malicious = vt.get("malicious_count", 0)
        if malicious > 3:
            _add(findings, "reputation", "CRITICAL", "rep_virustotal_malicious", rep,
                 detail=f"{malicious} vendors flag as malicious")
        elif malicious > 0:
            _add(findings, "reputation", "RED", "rep_virustotal_flagged", rep,
                 detail=f"{malicious} vendor(s) flag as suspicious")

    # URLScan malicious verdict
    urlscan = rep.get("urlscan") or {}
    if urlscan.get("checked") and urlscan.get("is_malicious"):
        _add(findings, "reputation", "RED", "rep_urlscan_malicious", rep)

    # LeakIX leaks found
    leakix = rep.get("leakix") or {}
    if leakix.get("checked") and leakix.get("leaks_found", 0) > 0:
        _add(findings, "reputation", "RED", "rep_leakix_leaks", rep,
             detail=f"{leakix['leaks_found']} leaks/exposed services found")


# ──────────────────────────────────────────────────
# Domain 10: Infrastructure
# ──────────────────────────────────────────────────
def _classify_infra(infra: dict, findings: list) -> None:
    if not infra:
        return

    # RED: Subdomain takeover risks
    takeover_risks = infra.get("takeover_risks", 0)
    if takeover_risks > 0:
        _add(findings, "infra", "RED", "infra_subdomain_takeover", infra,
             detail=f"{takeover_risks} subdomain(s) at risk of takeover")

    # AMBER: Typosquatting
    typo_count = infra.get("typosquat_count", 0)
    if typo_count > 10:
        _add(findings, "infra", "RED", "infra_typosquatting_high", infra,
             detail=f"{typo_count} registered lookalike domains")
    elif typo_count > 5:
        _add(findings, "infra", "AMBER", "infra_typosquatting_medium", infra,
             detail=f"{typo_count} registered lookalike domains")

    # AMBER: IP has abuse history
    ip_rep = infra.get("ip_reputation") or {}
    if ip_rep.get("is_known_bad"):
        _add(findings, "infra", "RED", "infra_ip_bad_reputation", infra,
             detail=f"Abuse score: {ip_rep.get('abuse_score', 0)}")

    # INFO: Subdomains found
    subs = infra.get("subdomains_found", 0)
    if subs > 0:
        _add(findings, "infra", "INFO", "infra_subdomains_discovered", infra,
             detail=f"{subs} subdomains discovered")

    # Email security
    email = infra.get("email_security") or {}
    if not email.get("has_mta_sts"):
        _add(findings, "infra", "GREEN", "infra_no_mta_sts", infra)
