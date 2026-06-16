"""
Classifier v2 — weighted scoring, WAF context, 15 modules, specific finding titles.
"""

import json
import logging
from typing import Any

from app.services.finding_content import get_finding_content

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"CRITICAL": 0, "RED": 1, "AMBER": 2, "GREEN": 3, "INFO": 4}

WAF_MITIGATED_KEYS = {
    "headers_some_missing",
    "headers_one_missing",
    "headers_many_missing",
    "headers_server_version_exposed",
    "headers_tech_stack_exposed",
}
STRONG_WAFS = {
    "Cloudflare",
    "AWS CloudFront",
    "Akamai",
    "Imperva",
    "Sucuri",
    "Azure Front Door",
}

SEVERITY_DOWNGRADE = {
    "CRITICAL": "RED",
    "RED": "AMBER",
    "AMBER": "GREEN",
    "GREEN": "INFO",
}


def classify_findings(raw: dict, waf_context: dict | None = None) -> list[dict]:
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
    _classify_javascript(raw.get("javascript") or {}, findings)
    _classify_cors(raw.get("cors") or {}, findings)
    _classify_http_methods(raw.get("http_methods") or {}, findings)
    _classify_waf(raw.get("waf") or {}, findings)
    _classify_cloud(raw.get("cloud") or {}, findings)
    _classify_brand_threats(raw.get("brand") or {}, findings)

    # WAF mitigation: downgrade header findings if strong WAF detected
    if waf_context and waf_context.get("waf_detected"):
        provider = waf_context.get("waf_provider", "")
        if provider in STRONG_WAFS:
            for f in findings:
                if f["key"] in WAF_MITIGATED_KEYS:
                    old = f["severity"]
                    f["severity"] = SEVERITY_DOWNGRADE.get(old, old)
                    f["waf_mitigated"] = True
                    f["waf_note"] = f"Risk partially mitigated by {provider} WAF"

    findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 5))
    return findings


def _add(
    findings: list, check: str, severity: str, key: str, data: dict, **extra: Any
) -> None:
    # Look up content from the catalog
    content = get_finding_content(
        key, default_title=extra.get("display_title") or extra.get("detail") or key
    )

    # Format evidence from raw data
    evidence_str = ""
    if isinstance(data, (dict, list)):
        try:
            evidence_str = json.dumps(data, indent=2)
        except Exception:
            evidence_str = str(data)
    else:
        evidence_str = str(data)

    finding = {
        "check": check,
        "severity": severity,
        "key": key,
        "data": data,  # Keep for backward compatibility
        "module": extra.pop("module", check),
        "proof_confirmed": extra.pop("proof_confirmed", False),
        "reachability": extra.pop("reachability", None),
        # New 5-part structure mapped to frontend RiskItem fields
        "title": content["title"],
        "observation": extra.pop("detail", content["observation"]),
        "business_impact": content["impact"],
        "evidence": evidence_str,
        "fix_action": content["remediation"],
        "verification_steps": content["verification"],
    }
    finding.update(extra)
    findings.append(finding)


# ── Brand Threat (Module 5) ──────────────────────────────────────────────────
def _classify_brand_threats(brand: dict, findings: list) -> None:
    """Classify brand protection threats from the brand_monitor module."""
    if not brand:
        return
    threats = brand.get("threats", [])
    for t in threats:
        threat_type = t.get("threat_type", "unknown")
        domain = t.get("domain", "")
        threat_level = t.get("threat_level", "MEDIUM")
        sim = t.get("similarity_score", 0.0)
        is_live = t.get("is_live", False)

        severity_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "RED",
            "MEDIUM": "AMBER",
            "LOW": "GREEN",
        }
        severity = severity_map.get(threat_level, "AMBER")

        label = {
            "typosquat": "Typosquatting Domain",
            "homoglyph": "Homoglyph/Impersonation Domain",
            "ct_alert": "CT Log Brand Alert",
        }
        key = {
            "typosquat": "brand_typosquat",
            "homoglyph": "brand_homoglyph",
            "ct_alert": "brand_ct_alert",
        }

        _add(
            findings,
            "brand",
            severity,
            key.get(threat_type, "brand_threat"),
            t,
            module="brand_monitor",
            display_title=label.get(threat_type, "Brand Threat"),
            suspicious_domain=domain,
            similarity_score=sim,
            is_live=is_live,
        )


# ── SSL/TLS ──
def _classify_ssl(ssl: dict, findings: list) -> None:
    if not ssl:
        return
    if ssl.get("heartbleed_vulnerable"):
        _add(findings, "ssl", "CRITICAL", "ssl_heartbleed", ssl)
    if ssl.get("robot_vulnerable"):
        _add(findings, "ssl", "CRITICAL", "ssl_robot", ssl)
    if not ssl.get("valid") and not ssl.get("error"):
        _add(findings, "ssl", "RED", "ssl_invalid", ssl)
    elif ssl.get("error"):
        _add(findings, "ssl", "RED", "ssl_unavailable", ssl)
    if ssl.get("is_self_signed"):
        _add(findings, "ssl", "RED", "ssl_self_signed", ssl)
    if ssl.get("supports_tls_1_0"):
        _add(findings, "ssl", "RED", "ssl_tls10_supported", ssl)
    if ssl.get("supports_tls_1_1"):
        _add(findings, "ssl", "RED", "ssl_tls11_supported", ssl)
    if ssl.get("has_null_cipher"):
        _add(findings, "ssl", "RED", "ssl_null_cipher", ssl)
    if ssl.get("has_rc4_cipher"):
        _add(findings, "ssl", "RED", "ssl_rc4_cipher", ssl)
    if ssl.get("has_des_cipher"):
        _add(findings, "ssl", "RED", "ssl_des_cipher", ssl)
    if ssl.get("has_export_cipher"):
        _add(findings, "ssl", "RED", "ssl_export_cipher", ssl)
    days = ssl.get("days_until_expiry", 999)
    if isinstance(days, (int, float)) and days < 14:
        _add(
            findings,
            "ssl",
            "RED",
            "ssl_expiring_critical",
            ssl,
            detail=f"Certificate expires in {int(days)} days",
        )
    elif isinstance(days, (int, float)) and days <= 30:
        _add(
            findings,
            "ssl",
            "AMBER",
            "ssl_expiring_soon",
            ssl,
            detail=f"Certificate expires in {int(days)} days",
        )
    if ssl.get("supports_tls_1_2") and not ssl.get("supports_tls_1_3"):
        _add(findings, "ssl", "AMBER", "ssl_no_tls13", ssl)
    if ssl.get("valid") and not ssl.get("has_ct_logs"):
        _add(findings, "ssl", "AMBER", "ssl_no_ct_logs", ssl)
    if ssl.get("valid") and not ssl.get("has_ocsp_stapling"):
        _add(findings, "ssl", "AMBER", "ssl_no_ocsp", ssl)
    if ssl.get("is_wildcard"):
        _add(findings, "ssl", "AMBER", "ssl_wildcard_cert", ssl)


# ── HTTP Headers ──
def _classify_headers(headers: dict, findings: list) -> None:
    if not headers:
        return
    missing = headers.get("missing", [])
    missing_names = ", ".join(missing[:6]) if missing else ""
    if len(missing) >= 4:
        _add(
            findings,
            "headers",
            "RED",
            "headers_many_missing",
            headers,
            detail=f"{len(missing)} of 13 Security Headers Missing: {missing_names}",
        )
    elif len(missing) >= 2:
        _add(
            findings,
            "headers",
            "AMBER",
            "headers_some_missing",
            headers,
            detail=f"{len(missing)} Security Headers Missing: {missing_names}",
        )
    elif len(missing) == 1:
        _add(
            findings,
            "headers",
            "GREEN",
            "headers_one_missing",
            headers,
            detail=f"1 Security Header Missing: {missing_names}",
        )
    if headers.get("server_exposes_version"):
        server_val = headers.get("server_header", "")
        _add(
            findings,
            "headers",
            "AMBER",
            "headers_server_version_exposed",
            headers,
            detail=f"Server header exposes: {server_val[:60]}",
        )
    if headers.get("xpowered_exposes_tech"):
        _add(findings, "headers", "AMBER", "headers_tech_stack_exposed", headers)
    if headers.get("referrer_unsafe"):
        _add(findings, "headers", "RED", "headers_unsafe_referrer", headers)
    redirect_info = headers.get("redirect_info") or {}
    if not redirect_info.get("http_to_https"):
        _add(findings, "headers", "RED", "headers_no_https_redirect", headers)
    if redirect_info.get("too_many_redirects"):
        _add(findings, "headers", "AMBER", "headers_too_many_redirects", headers)
    hsts_max = headers.get("hsts_max_age")
    if hsts_max is not None and hsts_max < 31536000:
        _add(findings, "headers", "AMBER", "headers_hsts_short_max_age", headers)
    if headers.get("csp_report_only"):
        _add(findings, "headers", "AMBER", "headers_csp_report_only", headers)
    # Robots.txt sensitive paths
    sensitive_robots = headers.get("robots_sensitive_paths", [])
    if sensitive_robots:
        _add(
            findings,
            "headers",
            "AMBER",
            "headers_robots_sensitive_paths",
            headers,
            detail=f"robots.txt discloses {len(sensitive_robots)} sensitive paths: {', '.join(sensitive_robots[:5])}",
        )
    # security.txt present
    if headers.get("has_security_txt"):
        _add(findings, "headers", "GREEN", "headers_security_txt_present", headers)


# ── DNS ──
def _classify_dns(dns_data: dict, findings: list) -> None:
    if not dns_data:
        return
    if dns_data.get("zone_transfer_possible"):
        _add(findings, "dns", "CRITICAL", "dns_zone_transfer", dns_data)
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
    dmarc = dns_data.get("dmarc") or {}
    if isinstance(dmarc, dict) and dmarc.get("policy") == "none":
        _add(
            findings,
            "dns",
            "AMBER",
            "dns_dmarc_not_enforced",
            dns_data,
            detail="DMARC Policy Not Enforced (p=none)",
        )
    elif dns_data.get("dmarc_not_enforced"):
        _add(findings, "dns", "AMBER", "dns_dmarc_not_enforced", dns_data)
    if dns_data.get("spf_too_many_lookups"):
        _add(findings, "dns", "AMBER", "dns_spf_too_many_lookups", dns_data)
    if not dns_data.get("has_dnssec"):
        _add(findings, "dns", "AMBER", "dns_no_dnssec", dns_data)
    if not dns_data.get("has_caa"):
        _add(findings, "dns", "AMBER", "dns_no_caa", dns_data)
    if not dns_data.get("has_dkim"):
        _add(findings, "dns", "GREEN", "dns_no_dkim", dns_data)
    subs = dns_data.get("discovered_subdomains", [])
    if subs:
        _add(
            findings,
            "dns",
            "INFO",
            "dns_subdomains_found",
            dns_data,
            detail=f"{len(subs)} common subdomains resolve",
        )
    # SMTP TLS
    if dns_data.get("smtp_no_starttls"):
        _add(findings, "dns", "AMBER", "dns_smtp_no_starttls", dns_data)
    # BIMI
    if dns_data.get("has_bimi"):
        _add(findings, "dns", "GREEN", "dns_bimi_present", dns_data)
    # MTA-STS
    if dns_data.get("has_mta_sts"):
        _add(findings, "dns", "GREEN", "dns_mta_sts_present", dns_data)


# ── Ports ──
def _classify_ports(ports: dict, findings: list) -> None:
    if not ports:
        return
    open_ports = ports.get("open_ports", [])
    db_ports = {3306, 5432, 27017, 6379, 9200}
    exposed_db = [p for p in open_ports if p in db_ports]
    if exposed_db:
        port_names = {
            3306: "MySQL",
            5432: "PostgreSQL",
            27017: "MongoDB",
            6379: "Redis",
            9200: "Elasticsearch",
        }
        names = [f"{port_names.get(p, p)} ({p})" for p in exposed_db]
        _add(
            findings,
            "ports",
            "CRITICAL",
            "ports_database_exposed",
            ports,
            detail=f"Database Ports Exposed to Internet: {', '.join(names)}",
        )
    red_ports = {21, 23, 3389, 5900, 445}
    exposed_red = [p for p in open_ports if p in red_ports]
    if exposed_red:
        port_names = {21: "FTP", 23: "Telnet", 3389: "RDP", 5900: "VNC", 445: "SMB"}
        names = [f"{port_names.get(p, p)} ({p})" for p in exposed_red]
        _add(
            findings,
            "ports",
            "RED",
            "dangerous_ports_exposed",
            ports,
            detail=f"Dangerous Services Exposed: {', '.join(names)}",
        )
    amber_ports = {8080, 8443, 8888}
    exposed_amber = [p for p in open_ports if p in amber_ports]
    if exposed_amber:
        _add(
            findings,
            "ports",
            "AMBER",
            "unusual_ports_open",
            ports,
            detail=f"Non-standard web ports open: {', '.join(str(p) for p in exposed_amber)}",
        )
    # SMB v1
    if ports.get("smbv1_enabled"):
        _add(findings, "ports", "CRITICAL", "ports_smbv1_enabled", ports)
    # Redis no auth
    if ports.get("redis_no_auth"):
        _add(findings, "ports", "CRITICAL", "ports_redis_no_auth", ports)


# ── Breach ──
def _classify_breach(breach: dict, findings: list) -> None:
    if not breach:
        return
    if breach.get("breached"):
        count = breach.get("breach_count", 0)
        _add(
            findings,
            "breach",
            "RED",
            "domain_in_breach",
            breach,
            detail=f"Domain Found in {count} Known Data Breaches",
        )


# ── CMS ──
def _classify_cms(cms: dict, findings: list) -> None:
    if not cms:
        return
    exposed_keys = cms.get("exposed_api_keys", [])
    if exposed_keys:
        _add(
            findings,
            "cms",
            "CRITICAL",
            "cms_api_keys_exposed",
            cms,
            detail=f"API Keys Found in Page Source: {', '.join(exposed_keys[:3])}",
        )
    # Admin panel — with false positive reduction
    admin_info = cms.get("admin_info") or {}
    if isinstance(admin_info, dict):
        if admin_info.get("no_auth_required"):
            _add(
                findings,
                "cms",
                "RED",
                "cms_admin_no_auth",
                cms,
                detail=f"Admin Panel Accessible Without Authentication at {admin_info.get('path', '/admin/')}",
            )
        elif admin_info.get("is_login_page"):
            _add(
                findings,
                "cms",
                "AMBER",
                "cms_admin_login_visible",
                cms,
                detail=f"Admin Login Page Visible at {admin_info.get('path', '/admin/')}",
            )
        elif admin_info.get("redirects_to_login"):
            _add(findings, "cms", "INFO", "cms_admin_redirects", cms)
    elif cms.get("admin_exposed"):
        _add(findings, "cms", "AMBER", "cms_admin_exposed", cms)
    install_files = cms.get("install_files_exposed", [])
    if install_files:
        _add(
            findings,
            "cms",
            "RED",
            "cms_install_files_exposed",
            cms,
            detail=f"Installation Files Left Behind: {', '.join(install_files[:3])}",
        )
    if cms.get("outdated_version"):
        detected = cms.get("detected_cms", "CMS")
        version = cms.get("cms_version", "unknown")
        _add(
            findings,
            "cms",
            "AMBER",
            "cms_outdated",
            cms,
            detail=f"{detected} Version {version} Is Outdated",
        )
    wp_vuln_plugins = cms.get("wp_vulnerable_plugins", 0)
    if wp_vuln_plugins > 0:
        _add(
            findings,
            "cms",
            "RED",
            "cms_wp_vulnerable_plugins",
            cms,
            detail=f"{wp_vuln_plugins} Vulnerable WordPress Plugins Detected",
        )
    wp_core_vulns = cms.get("wp_core_vulnerabilities", [])
    if wp_core_vulns:
        _add(
            findings,
            "cms",
            "RED",
            "cms_wp_core_vulnerable",
            cms,
            detail=f"{len(wp_core_vulns)} WordPress Core Vulnerabilities",
        )
    wp_users = cms.get("wp_users_found", [])
    if wp_users:
        _add(
            findings,
            "cms",
            "AMBER",
            "cms_wp_users_enumerated",
            cms,
            detail=f"WordPress Usernames Enumerable: {', '.join(wp_users[:3])}",
        )


# ── Cookies ──
def _classify_cookies(cookies: dict, findings: list) -> None:
    if not cookies:
        return
    if cookies.get("session_cookies_insecure"):
        _add(findings, "cookies", "RED", "session_cookie_insecure", cookies)
    elif not cookies.get("all_have_samesite", True):
        _add(findings, "cookies", "AMBER", "cookie_missing_samesite", cookies)


# ── Web Application ──
def _classify_webapp(webapp: dict, findings: list) -> None:
    if not webapp:
        return
    exposed_files = webapp.get("exposed_files", [])
    for ef in exposed_files:
        severity = ef.get("severity", "RED")
        path = ef.get("path", "")
        confirmed = ef.get("content_confirmed", False)
        if not confirmed and severity == "CRITICAL":
            severity = "RED"  # Downgrade if not content-confirmed
        key = f"webapp_exposed_{path.replace('/', '_').strip('_')}"
        _add(
            findings,
            "webapp",
            severity,
            key,
            webapp,
            detail=ef.get("description", f"Sensitive File Exposed: {path}"),
        )
    nuclei_findings = webapp.get("nuclei_findings", [])
    for nf in nuclei_findings:
        severity = nf.get("severity", "INFO")
        if severity in ("CRITICAL", "RED", "AMBER"):
            _add(
                findings,
                "webapp",
                severity,
                f"webapp_nuclei_{nf.get('template_id', 'unknown')}",
                webapp,
                detail=nf.get("name", ""),
            )
    obs = webapp.get("observatory") or {}
    grade = obs.get("grade")
    if grade and grade.startswith("F"):
        _add(
            findings,
            "webapp",
            "RED",
            "webapp_observatory_grade_f",
            webapp,
            detail=f"Mozilla Observatory Security Grade: {grade}",
        )
    elif grade and grade.startswith("D"):
        _add(
            findings,
            "webapp",
            "AMBER",
            "webapp_observatory_grade_d",
            webapp,
            detail=f"Mozilla Observatory Security Grade: {grade}",
        )
    if webapp.get("has_security_txt"):
        _add(findings, "webapp", "GREEN", "webapp_security_txt_present", webapp)


# ── Reputation ──
def _classify_reputation(rep: dict, findings: list) -> None:
    if not rep:
        return
    gsb = rep.get("safe_browsing") or {}
    if gsb.get("checked") and not gsb.get("is_safe"):
        threats = gsb.get("threats_found", [])
        _add(
            findings,
            "reputation",
            "CRITICAL",
            "rep_google_unsafe",
            rep,
            detail=f"Google Safe Browsing Flags: {', '.join(threats)}",
        )
    vt = rep.get("virustotal") or {}
    if vt.get("checked"):
        malicious = vt.get("malicious_count", 0)
        if malicious > 3:
            _add(
                findings,
                "reputation",
                "CRITICAL",
                "rep_virustotal_malicious",
                rep,
                detail=f"{malicious} Security Vendors Flag Domain as Malicious",
            )
        elif malicious > 0:
            _add(
                findings,
                "reputation",
                "RED",
                "rep_virustotal_flagged",
                rep,
                detail=f"{malicious} Security Vendor(s) Flag Domain as Suspicious",
            )
    urlscan = rep.get("urlscan") or {}
    if urlscan.get("checked") and urlscan.get("is_malicious"):
        _add(findings, "reputation", "RED", "rep_urlscan_malicious", rep)
    leakix = rep.get("leakix") or {}
    if leakix.get("checked") and leakix.get("leaks_found", 0) > 0:
        _add(
            findings,
            "reputation",
            "RED",
            "rep_leakix_leaks",
            rep,
            detail=f"{leakix['leaks_found']} Data Leaks/Exposed Services Found",
        )


# ── Infrastructure ──
def _classify_infra(infra: dict, findings: list) -> None:
    if not infra:
        return
    takeover_risks = infra.get("takeover_risks", 0)
    if takeover_risks > 0:
        _add(
            findings,
            "infra",
            "RED",
            "infra_subdomain_takeover",
            infra,
            detail=f"{takeover_risks} Subdomain(s) Vulnerable to Takeover",
        )
    typo_count = infra.get("typosquat_count", 0)
    if typo_count > 10:
        _add(
            findings,
            "infra",
            "RED",
            "infra_typosquatting_high",
            infra,
            detail=f"{typo_count} Registered Lookalike Domains Found",
        )
    elif typo_count > 5:
        _add(
            findings,
            "infra",
            "AMBER",
            "infra_typosquatting_medium",
            infra,
            detail=f"{typo_count} Registered Lookalike Domains Found",
        )
    ip_rep = infra.get("ip_reputation") or {}
    if ip_rep.get("is_known_bad"):
        _add(
            findings,
            "infra",
            "RED",
            "infra_ip_bad_reputation",
            infra,
            detail=f"IP Abuse Confidence Score: {ip_rep.get('abuse_score', 0)}%",
        )
    subs = infra.get("subdomains_found", 0)
    if subs > 0:
        _add(
            findings,
            "infra",
            "INFO",
            "infra_subdomains_discovered",
            infra,
            detail=f"{subs} Subdomains Discovered via Passive Enumeration",
        )


# ── JavaScript (NEW) ──
def _classify_javascript(js: dict, findings: list) -> None:
    if not js:
        return
    for secret in js.get("secrets_found", []):
        pt = secret.get("pattern_type", "")
        if pt in ("aws_access_key", "private_key", "stripe_key"):
            _add(
                findings,
                "javascript",
                "CRITICAL",
                "aws_key_in_source" if "aws" in pt else "api_key_in_source",
                js,
                detail=f"{pt.replace('_', ' ').title()} Pattern Detected in Client-Side Code",
            )
        else:
            _add(
                findings,
                "javascript",
                "RED",
                "api_key_in_source",
                js,
                detail=f"{pt.replace('_', ' ').title()} Pattern Detected in Client-Side Code",
            )
    for _sm in js.get("source_maps_exposed", []):
        _add(
            findings,
            "javascript",
            "RED",
            "source_map_exposed",
            js,
            detail="JavaScript Source Map Publicly Accessible",
        )
        break  # One finding even if multiple maps
    for lib in js.get("outdated_libraries", []):
        name = lib.get("name", "Library")
        ver = lib.get("detected_version", "?")
        sev = lib.get("severity", "AMBER")
        key = "jquery_outdated" if name == "jQuery" else "js_library_outdated"
        _add(
            findings,
            "javascript",
            sev,
            key,
            js,
            detail=f"{name} {ver} Is Outdated (minimum safe: {lib.get('min_safe', '?')})",
        )
    if js.get("mixed_content_urls"):
        count = len(js["mixed_content_urls"])
        _add(
            findings,
            "javascript",
            "AMBER",
            "mixed_content_detected",
            js,
            detail=f"{count} HTTP Resources Loaded on HTTPS Page (Mixed Content)",
        )
    if js.get("has_debug_code"):
        _add(
            findings,
            "javascript",
            "AMBER",
            "debug_code_in_production",
            js,
            detail=f"{js.get('debug_count', 0)} console.log Statements Found in Production Code",
        )


# ── CORS (NEW) ──
def _classify_cors(cors: dict, findings: list) -> None:
    if not cors:
        return
    for f in cors.get("findings", []):
        ftype = f.get("type", "")
        severity = f.get("severity", "AMBER")
        detail = f.get("detail", "")
        _add(findings, "cors", severity, ftype, cors, detail=detail)


# ── HTTP Methods (NEW) ──
def _classify_http_methods(methods: dict, findings: list) -> None:
    if not methods:
        return
    if methods.get("trace_reflected"):
        _add(
            findings,
            "http_methods",
            "CRITICAL",
            "trace_with_reflection",
            methods,
            detail="TRACE Method Enabled with Header Reflection (Cross-Site Tracing)",
        )
    elif methods.get("trace_enabled"):
        _add(
            findings,
            "http_methods",
            "RED",
            "trace_enabled",
            methods,
            detail="HTTP TRACE Method Enabled on Server",
        )
    dangerous = methods.get("dangerous_methods", [])
    non_trace = [m for m in dangerous if m != "TRACE"]
    if non_trace:
        _add(
            findings,
            "http_methods",
            "AMBER",
            "dangerous_methods_enabled",
            methods,
            detail=f"Potentially Dangerous HTTP Methods Enabled: {', '.join(non_trace)}",
        )


# ── WAF (NEW) ──
def _classify_waf(waf: dict, findings: list) -> None:
    if not waf:
        return
    if waf.get("waf_detected"):
        provider = waf.get("waf_provider", "Unknown")
        _add(
            findings,
            "waf",
            "GREEN",
            "waf_detected",
            waf,
            detail=f"Web Application Firewall Detected: {provider}",
        )
    elif waf.get("cdn_detected"):
        provider = waf.get("cdn_provider", "Unknown")
        _add(
            findings,
            "waf",
            "GREEN",
            "cdn_detected",
            waf,
            detail=f"CDN/Edge Protection Detected: {provider}",
        )


# ── Cloud Exposure (NEW) ──
def _classify_cloud(cloud: dict, findings: list) -> None:
    if not cloud:
        return
    for bucket in cloud.get("public_buckets", []):
        provider = bucket.get("provider", "Cloud")
        name = bucket.get("name", "unknown")
        _add(
            findings,
            "cloud",
            "CRITICAL",
            "public_cloud_bucket",
            cloud,
            detail=f"Publicly Listable {provider} Bucket: {name}",
        )
    for bucket in cloud.get("protected_buckets", []):
        name = bucket.get("name", "unknown")
        _add(
            findings,
            "cloud",
            "AMBER",
            "enumerable_cloud_bucket",
            cloud,
            detail=f"Cloud Bucket Name Enumerable (access denied): {name}",
        )
