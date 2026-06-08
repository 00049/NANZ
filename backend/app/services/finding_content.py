"""
Catalog of finding content mappings.
Provides structured Observation, Impact, Remediation, and Verification for findings.
"""

from typing import Dict, Any

_CATALOG: Dict[str, Dict[str, str]] = {
    "dns_no_spf": {
        "title": "Missing SPF Record",
        "observation": "No SPF (Sender Policy Framework) TXT record was detected on the domain.",
        "impact": "Without SPF, attackers can spoof emails appearing to come from your domain, leading to phishing attacks and brand damage.",
        "remediation": "Create a DNS TXT record for your domain with a valid SPF policy (e.g., v=spf1 mx -all).",
        "verification": "Run `dig TXT <domain>` and ensure a record starting with `v=spf1` is returned."
    },
    "dns_no_dmarc": {
        "title": "Missing DMARC Record",
        "observation": "No DMARC (Domain-based Message Authentication, Reporting, and Conformance) TXT record was found.",
        "impact": "Email receivers have no instructions on how to handle emails that fail SPF/DKIM checks, increasing spoofing risk.",
        "remediation": "Create a `_dmarc` TXT record with a policy (e.g., `v=DMARC1; p=quarantine; rua=mailto:reports@domain.com`).",
        "verification": "Run `dig TXT _dmarc.<domain>` and check for a `v=DMARC1` record."
    },
    "ssl_heartbleed": {
        "title": "Heartbleed Vulnerability",
        "observation": "The server is vulnerable to the Heartbleed bug (CVE-2014-0160) in its TLS implementation.",
        "impact": "Attackers can read the memory of the systems protected by the vulnerable OpenSSL versions, compromising secret keys and user data.",
        "remediation": "Update OpenSSL to the latest patched version and revoke/reissue all affected certificates.",
        "verification": "Use `nmap -p 443 --script ssl-heartbleed <target>` to verify the vulnerability is closed."
    },
    "headers_unsafe_referrer": {
        "title": "Unsafe Referrer Policy",
        "observation": "The application's Referrer-Policy allows leaking full URLs (which may contain sensitive tokens) to third-party sites.",
        "impact": "Sensitive session tokens or PII in the URL can be leaked to external analytics providers or external domains linked on the page.",
        "remediation": "Set the `Referrer-Policy` HTTP header to `strict-origin-when-cross-origin` or `no-referrer`.",
        "verification": "Inspect the HTTP response headers using `curl -I <url>` to confirm the Referrer-Policy is secure."
    },
    "ports_database_exposed": {
        "title": "Database Port Exposed",
        "observation": "A database service port (e.g., MySQL, PostgreSQL, Redis) is accessible from the public internet.",
        "impact": "Direct exposure of databases allows attackers to brute-force credentials, exploit database vulns, and steal sensitive data.",
        "remediation": "Restrict database access to internal network IP addresses or trusted VPN endpoints using firewall rules or security groups.",
        "verification": "Attempt to connect to the database port from an external IP using `nmap -p <port> -Pn <target>` and ensure it is blocked or filtered."
    },
    "cms_admin_no_auth": {
        "title": "Unauthenticated Admin Panel",
        "observation": "An administrative interface was discovered that does not require authentication.",
        "impact": "Anyone who discovers this URL can gain administrative access to the CMS, leading to complete site takeover.",
        "remediation": "Implement strong authentication (and ideally MFA) for all administrative interfaces. Restrict access by IP if possible.",
        "verification": "Attempt to access the admin URL in an incognito browser and ensure it redirects to a login prompt."
    },
    "session_cookie_insecure": {
        "title": "Insecure Session Cookie",
        "observation": "Session cookies are missing the 'Secure' or 'HttpOnly' flags.",
        "impact": "Cookies without the 'Secure' flag can be transmitted over plain HTTP. Cookies without 'HttpOnly' can be stolen via XSS.",
        "remediation": "Configure the web framework or application server to set `Secure` and `HttpOnly` flags on all session cookies.",
        "verification": "Inspect the `Set-Cookie` headers in the server response to ensure `Secure` and `HttpOnly` attributes are present."
    },
    "webapp_exposed_env": {
        "title": "Exposed Environment File",
        "observation": "An environment file (e.g., `.env`) is publicly accessible.",
        "impact": "Environment files typically contain highly sensitive secrets, database credentials, and API keys. This is a critical security breach.",
        "remediation": "Configure the web server to block access to all files starting with a dot (e.g., `/.env`) and move secrets to a secure vault.",
        "verification": "Attempt to fetch `/.env` via `curl <url>/.env` and ensure a 403 Forbidden or 404 Not Found is returned."
    },
    "api_key_in_source": {
        "title": "Hardcoded API Key",
        "observation": "A sensitive API key or secret was found hardcoded in the client-side JavaScript source code.",
        "impact": "Attackers can extract this key and impersonate the application, leading to data breaches or financial loss.",
        "remediation": "Remove the hardcoded secret from the source code. Fetch sensitive data server-side or use short-lived, scoped tokens.",
        "verification": "Review the updated source code to ensure the key is no longer present, and revoke the exposed key."
    },
    "trace_enabled": {
        "title": "HTTP TRACE Enabled",
        "observation": "The HTTP TRACE method is enabled on the web server.",
        "impact": "TRACE can be used in Cross-Site Tracing (XST) attacks to steal HttpOnly cookies.",
        "remediation": "Disable the TRACE method in your web server configuration (e.g., `TraceEnable off` in Apache).",
        "verification": "Run `curl -v -X TRACE <url>` and ensure a 405 Method Not Allowed is returned."
    }
}

def get_finding_content(key: str, default_title: str) -> Dict[str, str]:
    """
    Returns structured content for a finding.
    Provides generic fallbacks if the key is not explicitly mapped.
    """
    if key in _CATALOG:
        content = _CATALOG[key]
        return {
            "title": content.get("title", default_title),
            "observation": content.get("observation", "A security misconfiguration was detected."),
            "impact": content.get("impact", "Could be leveraged by an attacker to compromise application integrity or data confidentiality."),
            "remediation": content.get("remediation", "Review the finding details and apply security best practices to resolve the issue."),
            "verification": content.get("verification", "Retest the endpoint after applying the fix to ensure the vulnerability is resolved.")
        }
    
    # Generic fallback
    return {
        "title": default_title.replace("_", " ").title(),
        "observation": f"The scanner detected an issue related to: {default_title.replace('_', ' ')}.",
        "impact": "This issue may expose the application to unintended risks or information disclosure.",
        "remediation": "Investigate the affected component and configure it according to security best practices.",
        "verification": "Re-run the security scan to verify the issue is resolved."
    }
