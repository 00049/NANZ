from app.services.classifier import classify_findings

def test_ssl_invalid_gives_red():
    findings = classify_findings({"ssl": {"valid": False, "error": "cert expired"}})
    assert findings[0]["severity"] == "RED"
    assert findings[0]["key"] == "ssl_invalid"

def test_ssl_expiring_in_7_days_gives_red():
    findings = classify_findings({"ssl": {"valid": True, "days_until_expiry": 7}})
    assert findings[0]["severity"] == "RED"
    assert findings[0]["key"] == "ssl_expiring_critical"

def test_ssl_expiring_in_20_days_gives_amber():
    findings = classify_findings({"ssl": {"valid": True, "days_until_expiry": 20}})
    assert findings[0]["severity"] == "AMBER"
    assert findings[0]["key"] == "ssl_expiring_soon"

def test_three_missing_headers_gives_red():
    findings = classify_findings({"headers": {"missing": ["content-security-policy", "x-frame-options", "strict-transport-security"]}})
    assert findings[0]["severity"] == "RED"
    assert findings[0]["key"] == "headers_many_missing"

def test_one_missing_header_gives_amber():
    findings = classify_findings({"headers": {"missing": ["content-security-policy"]}})
    assert findings[0]["severity"] == "AMBER"
    assert findings[0]["key"] == "headers_some_missing"

def test_no_spf_and_no_dmarc_gives_red():
    findings = classify_findings({"dns": {"has_spf": False, "has_dmarc": False}})
    assert findings[0]["severity"] == "RED"
    assert findings[0]["key"] == "dns_no_email_protection"

def test_dangerous_port_3306_gives_red():
    findings = classify_findings({"ports": {"open_ports": [3306, 80]}})
    assert findings[0]["severity"] == "RED"
    assert findings[0]["key"] == "dangerous_ports_exposed"

def test_domain_in_breach_gives_red():
    findings = classify_findings({"breach": {"breached": True}})
    assert findings[0]["severity"] == "RED"
    assert findings[0]["key"] == "domain_in_breach"

def test_results_sorted_red_first():
    findings = classify_findings({
        "ssl": {"valid": True, "days_until_expiry": 20}, # AMBER
        "dns": {"has_spf": False, "has_dmarc": False},     # RED
        "ports": {"open_ports": [8080]}                    # AMBER
    })
    assert findings[0]["severity"] == "RED"
    assert findings[1]["severity"] == "AMBER"
    assert findings[2]["severity"] == "AMBER"

def test_max_three_results_returned():
    findings = classify_findings({
        "ssl": {"valid": False}, # RED
        "headers": {"missing": ["a", "b", "c"]}, # RED
        "dns": {"has_spf": False, "has_dmarc": False}, # RED
        "breach": {"breached": True}, # RED
        "ports": {"open_ports": [3306]} # RED
    })
    assert len(findings) == 3
