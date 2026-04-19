def classify_findings(raw: dict) -> list[dict]:
    """
    Evaluates raw scan findings against hard-coded security rules
    to determine severity (RED, AMBER, GREEN) before AI translation.
    Returns the top 3 critical findings.
    """
    findings = []
    
    # 1. SSL Rules
    if "ssl" in raw:
        ssl = raw.get("ssl") or {}
        if not ssl.get("valid") or ssl.get("error"):
            findings.append({"check": "ssl", "severity": "RED", "key": "ssl_invalid", "data": ssl})
        elif ssl.get("is_self_signed"):
            findings.append({"check": "ssl", "severity": "RED", "key": "ssl_self_signed", "data": ssl})
        elif ssl.get("days_until_expiry", 999) < 14:
            findings.append({"check": "ssl", "severity": "RED", "key": "ssl_expiring_critical", "data": ssl})
        elif ssl.get("days_until_expiry", 999) <= 30:
            findings.append({"check": "ssl", "severity": "AMBER", "key": "ssl_expiring_soon", "data": ssl})
        elif ssl.get("tls_version") in ["TLSv1", "TLSv1.1"]:
            findings.append({"check": "ssl", "severity": "AMBER", "key": "ssl_old_tls", "data": ssl})
        
    # 2. HTTP Headers Rules
    if "headers" in raw:
        headers = raw.get("headers") or {}
        missing = headers.get("missing", [])
        if len(missing) >= 3:
            findings.append({"check": "headers", "severity": "RED", "key": "headers_many_missing", "data": headers})
        elif 1 <= len(missing) <= 2:
            findings.append({"check": "headers", "severity": "AMBER", "key": "headers_some_missing", "data": headers})
        
    # 3. DNS Rules
    if "dns" in raw:
        dns = raw.get("dns") or {}
        has_spf = dns.get("has_spf", False)
        has_dmarc = dns.get("has_dmarc", False)
        if not has_spf and not has_dmarc:
            findings.append({"check": "dns", "severity": "RED", "key": "dns_no_email_protection", "data": dns})
        elif not has_spf or not has_dmarc:
            findings.append({"check": "dns", "severity": "AMBER", "key": "dns_partial_protection", "data": dns})
        
    # 4. Port Rules
    if "ports" in raw:
        ports = raw.get("ports") or {}
        open_ports = ports.get("open_ports", [])
        if any(p in [21, 23, 3306, 5432, 27017, 6379] for p in open_ports):
            findings.append({"check": "ports", "severity": "RED", "key": "dangerous_ports_exposed", "data": ports})
        elif any(p in [8080, 8443, 8888] for p in open_ports):
            findings.append({"check": "ports", "severity": "AMBER", "key": "unusual_ports_open", "data": ports})
        
    # 5. Breach Rules
    if "breach" in raw:
        breach = raw.get("breach") or {}
        if breach.get("breached"):
            findings.append({"check": "breach", "severity": "RED", "key": "domain_in_breach", "data": breach})
        
    # 6. CMS Rules
    if "cms" in raw:
        cms = raw.get("cms") or {}
        if cms.get("admin_exposed"):
            findings.append({"check": "cms", "severity": "RED", "key": "cms_admin_exposed", "data": cms})
        elif cms.get("outdated_version"):
            findings.append({"check": "cms", "severity": "AMBER", "key": "cms_outdated", "data": cms})
        
    # 7. Cookie Rules
    if "cookies" in raw:
        cookies = raw.get("cookies") or {}
        if cookies.get("session_cookies_insecure"):
            findings.append({"check": "cookies", "severity": "RED", "key": "session_cookie_insecure", "data": cookies})
        elif not cookies.get("all_have_samesite", True):
            findings.append({"check": "cookies", "severity": "AMBER", "key": "cookie_missing_samesite", "data": cookies})
        
    # Sort and return top 3
    order = {"RED": 0, "AMBER": 1, "GREEN": 2}
    findings.sort(key=lambda x: order.get(x["severity"], 3))
    
    return findings[:3]
