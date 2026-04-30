"""
Expanded AI Translator — now generates 3 types of text per finding:
1. business_impact — plain English for business owner (no jargon)
2. technical_detail — one technical sentence for developer
3. executive_summary — overall 3-4 sentence summary for entire scan

Same rules as before: severity from classifier, retry once, static fallbacks,
jargon filter on business_impact.
"""

import json
import hashlib
import logging
import re
from typing import List, Dict, Any
from anthropic import AsyncAnthropic

from app.config import settings
from app.schemas.report import RiskItem

logger = logging.getLogger(__name__)

# List of words to aggressively filter out to ensure plain English
JARGON_BLOCKLIST = [
    "CVE", "CVSS", "TLS", "SSL", "HSTS", "CSP", "DNS", "HTTP", "HTTPS",
    "API", "XSS", "SQLI", "OWASP", "TCP", "UDP", "RFC", "MIME", "DOM", "regex",
    "AXFR", "DMARC", "SPF", "DKIM", "DNSSEC", "CAA", "OCSP", "CNAME",
]

STATIC_FALLBACKS = {
    # ── SSL (Domain 1) ──
    "ssl_invalid": ("Website Identity Error", "Visitors will see a warning that your site is unsafe, causing them to leave.", "The SSL/TLS certificate is invalid or not trusted by browsers.", "Contact your website host to fix your security certificate.", "HIGH", "Easy", "5 minutes"),
    "ssl_expiring_critical": ("Security Warning Imminent", "Your website will soon show a 'Not Secure' warning to all users.", "Certificate expiry within 14 days triggers browser security warnings.", "Renew your security certificate with your hosting provider immediately.", "HIGH", "Easy", "10 minutes"),
    "ssl_expiring_soon": ("Security Renewal Needed", "If ignored, customers may lose trust when your site shows warnings.", "Certificate expiry within 30 days requires proactive renewal.", "Plan to renew your security certificate within the next few weeks.", "MEDIUM", "Easy", "10 minutes"),
    "ssl_self_signed": ("Untrusted Security", "Customers will see a scary red warning blocking them from your store.", "Self-signed certificate is not trusted by any browser CA store.", "Purchase a recognized security certificate from a trusted provider.", "HIGH", "Medium", "30 minutes"),
    "ssl_old_tls": ("Outdated Security Tech", "Old devices might be vulnerable when connecting to your store.", "Server supports deprecated TLS 1.0/1.1 protocols.", "Ask your host to disable older connection protocols.", "MEDIUM", "Easy", "15 minutes"),
    "ssl_tls10_supported": ("Obsolete Connection Protocol", "Attackers can intercept data sent using outdated connection methods.", "TLS 1.0 is deprecated and vulnerable to BEAST/POODLE attacks.", "Disable TLS 1.0 in your server configuration.", "HIGH", "Easy", "15 minutes"),
    "ssl_tls11_supported": ("Outdated Connection Protocol", "Some connections to your site use a weak protocol.", "TLS 1.1 is deprecated and should be disabled.", "Disable TLS 1.1 in your server configuration.", "HIGH", "Easy", "15 minutes"),
    "ssl_heartbleed": ("Critical Server Vulnerability", "Attackers can steal passwords and private data from your server's memory.", "Server is vulnerable to Heartbleed (CVE-2014-0160) — memory leak in OpenSSL.", "Update OpenSSL immediately and reissue all certificates.", "HIGH", "Hard", "2 hours"),
    "ssl_robot": ("Encryption Bypass Risk", "Attackers may be able to decrypt past communications to your site.", "Server vulnerable to ROBOT attack — RSA key exchange vulnerability.", "Disable RSA key exchange and switch to ECDHE cipher suites.", "HIGH", "Medium", "1 hour"),
    "ssl_null_cipher": ("No Encryption Available", "Some connections to your site may send data completely unencrypted.", "NULL cipher suites allow unencrypted connections.", "Remove NULL cipher suites from server configuration.", "HIGH", "Easy", "15 minutes"),
    "ssl_rc4_cipher": ("Weak Encryption", "Data sent using outdated encryption can be cracked by attackers.", "RC4 cipher suite is cryptographically broken.", "Disable RC4 cipher suites.", "HIGH", "Easy", "15 minutes"),
    "ssl_no_tls13": ("Missing Latest Encryption", "Your site doesn't support the strongest connection standard.", "TLS 1.3 not enabled — faster and more secure than TLS 1.2.", "Enable TLS 1.3 support in your server configuration.", "MEDIUM", "Easy", "15 minutes"),
    "ssl_no_ct_logs": ("Missing Transparency", "If someone creates a fake certificate for your site, you won't know.", "Certificate not logged in Certificate Transparency logs.", "Use a CA that publishes to CT logs.", "MEDIUM", "Easy", "10 minutes"),
    "ssl_no_ocsp": ("Slow Security Checks", "Browsers take longer to verify your site's security.", "OCSP stapling not enabled — slower certificate validation.", "Enable OCSP stapling in your server configuration.", "MEDIUM", "Easy", "15 minutes"),
    "ssl_wildcard_cert": ("Broad Certificate Scope", "A single compromised key affects all your subdomains.", "Wildcard certificate covers *.domain — broad attack surface.", "Consider individual certificates for sensitive subdomains.", "LOW", "Medium", "1 hour"),

    # ── Headers (Domain 2) ──
    "headers_many_missing": ("{missing_count} of 13 Security Headers Missing", "Hackers have an easier time tricking your website into doing malicious things.", "4+ critical security headers missing from HTTP response.", "Ask your developer to add standard web security guardrails.", "HIGH", "Medium", "1 hour"),
    "headers_some_missing": ("{missing_count} Security Headers Missing", "Some pages might be vulnerable to being embedded in fake sites.", "2-3 security headers missing from HTTP response.", "Have your web team review and update your site's protection settings.", "MEDIUM", "Easy", "30 minutes"),
    "headers_one_missing": ("1 Security Header Missing", "A small security improvement is available for your site.", "One security header missing from HTTP response.", "Add the missing security header.", "LOW", "Easy", "10 minutes"),
    "headers_no_https_redirect": ("Insecure Access Available", "Visitors can access your site without encryption.", "No HTTP to HTTPS redirect configured.", "Set up automatic redirect from HTTP to HTTPS.", "HIGH", "Easy", "15 minutes"),
    "headers_server_version_exposed": ("Server Info Leaked", "Attackers can see which server software you use and find known exploits.", "Server header exposes software version information.", "Configure server to hide version information.", "MEDIUM", "Easy", "10 minutes"),
    "headers_tech_stack_exposed": ("Tech Stack Revealed", "Attackers know what technology your site uses, making targeted attacks easier.", "X-Powered-By header reveals backend technology.", "Remove X-Powered-By header from server response.", "MEDIUM", "Easy", "10 minutes"),
    "headers_unsafe_referrer": ("URL Leakage Risk", "Your full page URLs are being shared with other websites.", "Referrer-Policy set to unsafe-url — leaks full URL to third parties.", "Change Referrer-Policy to strict-origin-when-cross-origin.", "HIGH", "Easy", "5 minutes"),

    # ── DNS (Domain 3) ──
    "dns_no_email_protection": ("Email Spoofing Risk", "Scammers can send fake emails pretending to be from your business.", "No SPF or DMARC records configured for email authentication.", "Set up specific records with your domain provider to prove emails are really from you.", "HIGH", "Medium", "30 minutes"),
    "dns_partial_protection": ("Incomplete Email Security", "Some spoofed emails might still reach your customers.", "Either SPF or DMARC is missing.", "Complete your domain email security setup.", "MEDIUM", "Easy", "15 minutes"),
    "dns_no_spf": ("No Email Sender Verification", "Anyone can send emails that appear to come from your domain.", "SPF record not configured.", "Add SPF TXT record to your DNS.", "MEDIUM", "Easy", "15 minutes"),
    "dns_no_dmarc": ("No Email Policy Set", "Email providers don't know how to handle spoofed emails from your domain.", "DMARC record not configured.", "Add DMARC TXT record to your DNS.", "MEDIUM", "Easy", "15 minutes"),
    "dns_zone_transfer": ("Complete Domain Data Exposed", "Anyone can download your entire domain configuration including all subdomains.", "DNS zone transfer (AXFR) is allowed — full zone data is public.", "Restrict AXFR to authorized nameservers only.", "HIGH", "Medium", "30 minutes"),
    "dns_dmarc_not_enforced": ("Email Policy Too Weak", "Spoofed emails from your domain are not being blocked.", "DMARC policy set to 'none' — no enforcement.", "Change DMARC policy to quarantine or reject.", "MEDIUM", "Easy", "5 minutes"),
    "dns_spf_plus_all": ("All Senders Allowed", "Literally anyone in the world can send emails as your business.", "SPF record uses +all — permits all senders.", "Change +all to ~all or -all in SPF record.", "HIGH", "Easy", "5 minutes"),
    "dns_no_dnssec": ("Domain Tampering Possible", "Attackers could redirect your website visitors to fake sites.", "DNSSEC not enabled for domain.", "Enable DNSSEC with your domain registrar.", "MEDIUM", "Medium", "1 hour"),
    "dns_no_caa": ("Certificate Control Missing", "Anyone can create security certificates for your domain.", "No CAA records limit which authorities can issue certificates.", "Add CAA DNS records specifying authorized certificate issuers.", "MEDIUM", "Easy", "10 minutes"),
    "dns_no_dkim": ("Email Verification Incomplete", "Emails from your domain may be harder to verify as legitimate.", "No DKIM records found for common selectors.", "Configure DKIM signing for your email service.", "LOW", "Medium", "30 minutes"),

    # ── Ports (Domain 4) ──
    "ports_database_exposed": ("Database Openly Accessible", "Your database is visible to the entire internet — critical data theft risk.", "Database port (MySQL/PostgreSQL/MongoDB/Redis/ES) exposed to internet.", "Firewall off database ports immediately — only allow internal access.", "HIGH", "Easy", "15 minutes"),
    "dangerous_ports_exposed": ("Critical Open Doors", "Highly sensitive internal systems are visible to anyone on the internet.", "Dangerous ports (FTP/Telnet/RDP/VNC/SMB) exposed.", "Firewall off these technical access points immediately.", "HIGH", "Easy", "15 minutes"),
    "unusual_ports_open": ("Unnecessary Access Points", "Extra doors to your server provide more ways for attackers to get in.", "Non-standard web ports (8080/8443/8888) are open.", "Close access to any background services that do not need to be public.", "MEDIUM", "Easy", "15 minutes"),

    # ── Breach ──
    "domain_in_breach": ("Data Leak History", "Information related to your company was found in a past internet hack.", "Domain found in known data breach databases.", "Ensure all staff use strong, different passwords and multi-factor authentication.", "HIGH", "Medium", "1 hour"),

    # ── CMS (Domain 7) ──
    "cms_admin_exposed": ("Admin Panel Visible", "Attackers can easily find where to brute-force your website login.", "Admin panel/login page publicly accessible.", "Hide or protect your website builder's login page.", "HIGH", "Medium", "30 minutes"),
    "cms_outdated": ("Old Website Software", "Hackers can exploit known flaws in older software to take over your site.", "CMS version is outdated — patches may be missing.", "Update your website builder software to the latest version.", "MEDIUM", "Easy", "30 minutes"),
    "cms_api_keys_exposed": ("Secret Keys In Public", "Attackers can use your exposed payment or cloud keys to steal money or data.", "API keys (Stripe/AWS/Google) found in page HTML source.", "Immediately rotate all exposed API keys and move them to server-side code.", "HIGH", "Medium", "1 hour"),
    "cms_wp_vulnerable_plugins": ("Vulnerable Add-ons Found", "Known security holes in your website add-ons could let hackers take over.", "WordPress plugins with known CVEs detected.", "Update or remove the vulnerable WordPress plugins.", "HIGH", "Easy", "30 minutes"),
    "cms_install_files_exposed": ("Setup Files Left Behind", "Installation files could allow attackers to reconfigure your website.", "Installation/setup files still publicly accessible.", "Delete installation files from the web server.", "HIGH", "Easy", "5 minutes"),

    # ── Cookies ──
    "session_cookie_insecure": ("Insecure User Logins", "Customer login sessions could be copied over public Wi-Fi.", "Session cookies missing Secure/HttpOnly flags.", "Enforce secure-only transmission for all user sessions.", "HIGH", "Easy", "15 minutes"),
    "cookie_missing_samesite": ("Tracking Vulnerability", "Your site could be manipulated from other malicious websites.", "Cookies missing SameSite attribute.", "Update your site's cookie settings to restrict cross-site tracking.", "MEDIUM", "Easy", "10 minutes"),

    # ── Webapp (Domain 5) ──
    "webapp_exposed_.git_config": ("Source Code Exposed", "Your entire website code including passwords is downloadable by anyone.", ".git/config file publicly accessible — full source code exposure.", "Block public access to .git directory immediately.", "HIGH", "Easy", "5 minutes"),
    "webapp_exposed_.env": ("Credentials File Exposed", "All your passwords, API keys, and secrets are readable by anyone.", ".env file publicly accessible — contains credentials.", "Block public access to .env file immediately.", "HIGH", "Easy", "5 minutes"),
    "webapp_observatory_grade_f": ("Failed Security Audit", "Your website fails a major security standards test by Mozilla.", "Mozilla HTTP Observatory grade F — multiple security issues.", "Review Mozilla Observatory report and fix identified issues.", "HIGH", "Medium", "2 hours"),

    # ── Reputation (Domain 6) ──
    "rep_google_unsafe": ("Flagged as Dangerous", "Google is warning visitors that your website may harm their computer.", "Google Safe Browsing flags domain for malware or phishing.", "Investigate and clean any malware, then request review from Google.", "HIGH", "Hard", "4 hours"),
    "rep_virustotal_malicious": ("Multiple Security Warnings", "Several security companies have flagged your website as dangerous.", "3+ VirusTotal vendors classify domain as malicious.", "Investigate hosting for malware and request de-listing.", "HIGH", "Hard", "4 hours"),
    "rep_leakix_leaks": ("Exposed Services Detected", "Security researchers found data leaks or exposed services on your domain.", "LeakIX reports exposed services or data leaks.", "Review and secure exposed services.", "HIGH", "Medium", "2 hours"),

    # ── Infra (Domain 8) ──
    "infra_subdomain_takeover": ("Subdomain Hijacking Risk", "Attackers could take over unused website addresses tied to your domain.", "Subdomain(s) pointing to unclaimed third-party services.", "Remove or reclaim dangling DNS records.", "HIGH", "Medium", "30 minutes"),
    "infra_typosquatting_high": ("Phishing Domain Alert", "Many fake versions of your domain exist — scammers may be targeting your customers.", "10+ registered typosquatting domains detected.", "Monitor and consider domain name protection services.", "MEDIUM", "Hard", "ongoing"),
    "infra_ip_bad_reputation": ("Bad Server Reputation", "Your server's address has been reported for abuse or malicious activity.", "IP address has high abuse confidence score.", "Contact hosting provider or consider migrating to clean IP.", "HIGH", "Hard", "variable"),

    # ── JavaScript (NEW) ──
    "aws_key_in_source": ("Cloud Access Key Exposed in Website Code", "Your cloud infrastructure credentials are publicly readable — anyone can access or delete your cloud storage and servers.", "AWS access key (AKIA prefix) found in client-side JavaScript source code.", "Immediately revoke this key in your cloud console, then remove it from code and use environment variables instead.", "HIGH", "Medium", "30 minutes"),
    "api_key_in_source": ("Secret Key Found in Website Code", "A secret access key is visible in your website code — attackers can use it to access your paid services.", "API key pattern detected in client-side JavaScript or HTML source.", "Remove the key from frontend code, rotate it, and move it to server-side environment variables.", "HIGH", "Medium", "30 minutes"),
    "source_map_exposed": ("Website Source Code Readable", "Your original source code is downloadable, revealing business logic and potential vulnerabilities.", "JavaScript source map (.map) file publicly accessible — exposes unminified source.", "Delete .map files from production or restrict access via server configuration.", "HIGH", "Easy", "10 minutes"),
    "jquery_outdated": ("Outdated Website Framework", "Your website uses an old version of a common tool with known security flaws.", "jQuery version below 3.0.0 — multiple known XSS vulnerabilities.", "Update jQuery to the latest version (3.7+).", "HIGH", "Easy", "30 minutes"),
    "js_library_outdated": ("Outdated Code Library", "Your website uses an old library version that may have security issues.", "JavaScript library version is below recommended minimum.", "Update the library to its latest stable version.", "MEDIUM", "Easy", "30 minutes"),
    "mixed_content_detected": ("Insecure Resources on Secure Page", "Some parts of your secure page load without encryption, weakening overall security.", "HTTP resources loaded on HTTPS page — mixed content vulnerability.", "Update all resource URLs to use secure connections.", "MEDIUM", "Easy", "20 minutes"),
    "debug_code_in_production": ("Developer Debug Code Left In", "Debug messages in your live site can reveal internal workings to attackers.", "Excessive console.log statements found in production JavaScript.", "Remove or disable debug logging before deploying to production.", "MEDIUM", "Easy", "15 minutes"),

    # ── CORS (NEW) ──
    "cors_credentials_wildcard": ("Any Website Can Read Your Logged-In Users Data", "A malicious website can silently steal your customers data by making requests to your site while they are logged in.", "CORS policy allows any origin with credentials — Access-Control-Allow-Origin: * with credentials.", "Update your server to only allow your specific domain in cross-origin settings, not wildcard.", "HIGH", "Easy", "15 minutes"),
    "cors_reflected_origin": ("Cross-Site Data Theft Possible", "Any website can trick your server into sharing data by pretending to be a trusted site.", "Server reflects arbitrary Origin header in ACAO — allows cross-origin data theft.", "Configure an explicit whitelist of allowed origins instead of reflecting the request origin.", "HIGH", "Easy", "15 minutes"),
    "cors_wildcard_api": ("Data Endpoint Open to All Websites", "Your data endpoints can be read by any website, potentially exposing customer information.", "Wildcard CORS on API endpoint — any origin can read responses.", "Restrict cross-origin access to only your own domains.", "HIGH", "Easy", "15 minutes"),
    "cors_null_origin": ("Sandbox Bypass Vulnerability", "Malicious content in embedded frames can read your website data.", "Server accepts null Origin — allows sandboxed iframe data access.", "Block null origin in your server's cross-origin configuration.", "HIGH", "Easy", "10 minutes"),
    "cors_wildcard_html": ("Loose Cross-Site Policy", "Your website allows any other site to embed and read its content.", "Wildcard CORS on HTML page — lower risk but indicates loose policy.", "Consider restricting cross-origin access.", "MEDIUM", "Easy", "10 minutes"),

    # ── HTTP Methods (NEW) ──
    "trace_with_reflection": ("Server Echoes Back Sensitive Data", "Attackers can steal login cookies by tricking the server into echoing them back.", "TRACE method enabled with header reflection — Cross-Site Tracing (XST) confirmed.", "Disable TRACE method in your web server configuration immediately.", "HIGH", "Easy", "10 minutes"),
    "trace_enabled": ("Debugging Protocol Left On", "A server debugging feature is active that could help attackers steal information.", "HTTP TRACE method is enabled on the server.", "Disable TRACE method in your web server configuration.", "HIGH", "Easy", "10 minutes"),
    "dangerous_methods_enabled": ("Extra Server Commands Available", "Your server accepts commands that could be used to modify or delete content.", "Potentially dangerous HTTP methods (PUT/DELETE/CONNECT) enabled.", "Disable unnecessary HTTP methods in server configuration.", "MEDIUM", "Easy", "15 minutes"),

    # ── WAF (NEW) ──
    "waf_detected": ("Web Firewall Active", "Your website is protected by a security firewall that blocks common attacks.", "WAF/CDN detected — provides DDoS protection and attack filtering.", "Good security practice — maintain WAF configuration.", "LOW", "Easy", "N/A"),
    "cdn_detected": ("Content Delivery Network Active", "Your website uses a content delivery network for performance and basic protection.", "CDN detected — provides caching and some security benefits.", "Good practice — CDN provides performance and basic DDoS protection.", "LOW", "Easy", "N/A"),

    # ── Cloud Exposure (NEW) ──
    "public_cloud_bucket": ("Public Cloud Storage Accessible", "Anyone on the internet can list and download all files stored in your cloud storage.", "S3/GCS/Azure bucket is publicly listable with no authentication required.", "Log into your cloud provider console and set the bucket to private immediately.", "HIGH", "Easy", "10 minutes"),
    "enumerable_cloud_bucket": ("Cloud Storage Name Discoverable", "Attackers know your cloud storage exists, which helps them plan targeted attacks.", "Cloud bucket name matches domain pattern — access denied but existence confirmed.", "Rename bucket to non-guessable name or ensure all access policies are strict.", "MEDIUM", "Medium", "30 minutes"),

    # ── Expanded Existing ──
    "headers_robots_sensitive_paths": ("Sensitive Paths Disclosed in Robots File", "Your robots file reveals internal paths that attackers can target.", "robots.txt Disallow entries expose admin/backup/config paths.", "Review robots.txt and remove references to sensitive directories.", "MEDIUM", "Easy", "10 minutes"),
    "headers_security_txt_present": ("Security Contact Published", "Security researchers can responsibly report issues to you.", "security.txt file present per RFC 9116.", "Good practice — maintain up-to-date security contact information.", "LOW", "Easy", "N/A"),
    "dns_smtp_no_starttls": ("Email Sent Without Encryption", "Emails sent from your domain may be readable by anyone who intercepts them.", "Mail server does not support STARTTLS — emails transmitted in plaintext.", "Enable STARTTLS on your mail server or use a provider that supports it.", "MEDIUM", "Medium", "1 hour"),
    "dns_bimi_present": ("Brand Email Indicator Active", "Your emails display your brand logo, increasing customer trust.", "BIMI record configured — brand indicator for email authentication.", "Good practice — maintain BIMI record.", "LOW", "Easy", "N/A"),
    "dns_mta_sts_present": ("Strict Email Transport Active", "Your email transport is secured against downgrade attacks.", "MTA-STS policy configured — enforces encrypted email delivery.", "Good practice — maintain MTA-STS policy.", "LOW", "Easy", "N/A"),
    "ports_smbv1_enabled": ("Critical File Sharing Vulnerability", "Your server uses an old file sharing protocol exploited by major ransomware attacks.", "SMBv1 enabled — vulnerable to EternalBlue/WannaCry exploits.", "Disable SMBv1 immediately and use SMBv3.", "HIGH", "Easy", "15 minutes"),
    "ports_redis_no_auth": ("Database Accessible Without Password", "Your in-memory database is completely open — anyone can read, modify, or delete all data.", "Redis port 6379 exposed with no authentication configured.", "Set a strong password for Redis and firewall the port.", "HIGH", "Easy", "10 minutes"),
    "cms_admin_no_auth": ("Admin Panel Open Without Login", "Anyone can access your website admin panel without a password.", "Admin panel accessible without authentication — no login required.", "Immediately add authentication or restrict access by IP.", "HIGH", "Easy", "15 minutes"),
    "cms_admin_login_visible": ("Admin Login Page Publicly Visible", "Attackers know where your admin login is and can try to guess passwords.", "Admin login page publicly accessible — brute force target.", "Consider hiding admin URL or adding rate limiting.", "MEDIUM", "Medium", "30 minutes"),
    "cms_admin_redirects": ("Admin Area Properly Protected", "Your admin area correctly requires login before access.", "Admin path redirects to authentication — properly configured.", "Good practice — admin area is protected.", "LOW", "Easy", "N/A"),
}


async def _call_claude(classified: List[Dict[str, Any]], domain: str) -> str:
    """Call Claude to translate pre-classified findings into plain English."""
    client = AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)

    system_prompt = """You are a cybersecurity advisor writing for a small business owner with zero technical background. You receive pre-classified security findings and write plain-English explanations.
STRICT RULES:
- Never use these terms: CVE, CVSS, TLS, SSL, HSTS, CSP, DNS, HTTP, HTTPS, API, XSS, SQLI, OWASP, TCP, UDP, RFC, MIME, DOM, regex, AXFR, DMARC, SPF, DKIM, DNSSEC, CNAME, OCSP
- Write as if explaining to a market shop owner, not an engineer
- Focus on business impact: money lost, customers scared, reputation damage
- Keep title under 12 words
- Keep business_impact to 1 sentence
- Keep technical_detail to 1 technical sentence (this one CAN use technical terms)
- Keep fix_action to 1 sentence, non-technical, actionable today
- NEVER change the severity field — copy it exactly from the input
- Set fix_difficulty to "Easy", "Medium", or "Hard"
- Set estimated_fix_time to a short time estimate like "5 minutes", "1 hour"
- Return ONLY a valid JSON array. No preamble. No markdown. No explanation.

Each item in the output array must have these exact fields:
  title, severity, business_impact, technical_detail, fix_action, fix_difficulty, estimated_fix_time, confidence"""

    user_prompt = f"Here are the findings for {domain}:\n\n{json.dumps(classified[:15], indent=2)}\n\nGenerate the plain English JSON array as instructed."

    response = await client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=3000,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}]
    )

    return response.content[0].text.strip()


async def _generate_executive_summary(classified: List[Dict[str, Any]], domain: str) -> str:
    """Generate a 3-4 sentence executive summary using Claude."""
    if not settings.ANTHROPIC_API_KEY:
        return _static_executive_summary(classified, domain)

    try:
        client = AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)

        critical_count = sum(1 for f in classified if f.get("severity") == "CRITICAL")
        red_count = sum(1 for f in classified if f.get("severity") == "RED")
        amber_count = sum(1 for f in classified if f.get("severity") == "AMBER")
        total = len(classified)

        prompt = f"""Write a 3-4 sentence executive summary for {domain}'s security scan.
Stats: {total} findings total, {critical_count} critical, {red_count} high-risk, {amber_count} medium-risk.
Top issues: {', '.join(f.get('key', '') for f in classified[:5])}

Rules:
- Write for a business owner with ZERO technical knowledge
- Never use: CVE, TLS, SSL, DNS, HTTP, API, XSS, SQL or any tech jargon
- Focus on business risk: customer trust, revenue impact, legal exposure
- Be direct and actionable
- Return ONLY the summary text, nothing else."""

        response = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}]
        )

        summary = response.content[0].text.strip()
        return _strip_jargon(summary)

    except Exception as e:
        logger.error(f"Executive summary generation failed: {e}")
        return _static_executive_summary(classified, domain)


def _static_executive_summary(classified: list, domain: str) -> str:
    """Generate a static executive summary without AI."""
    critical = sum(1 for f in classified if f.get("severity") == "CRITICAL")
    red = sum(1 for f in classified if f.get("severity") == "RED")
    amber = sum(1 for f in classified if f.get("severity") == "AMBER")
    total = len(classified)

    if critical > 0:
        return (
            f"Your website {domain} has {critical} critical security issues that need immediate attention. "
            f"These include exposed databases, leaked credentials, or malware detection that put your business and customers at serious risk. "
            f"We also found {red} high-risk and {amber} medium-risk issues. "
            f"We recommend addressing the critical issues within 24 hours."
        )
    elif red > 0:
        return (
            f"Your website {domain} has {red} high-risk security issues that should be addressed soon. "
            f"These could allow attackers to access sensitive information or impersonate your business. "
            f"We also found {amber} medium-risk issues for a total of {total} findings. "
            f"We recommend fixing the high-risk issues this week."
        )
    elif amber > 0:
        return (
            f"Your website {domain} has {amber} moderate security improvements available. "
            f"While no critical vulnerabilities were found, these improvements would strengthen your security posture. "
            f"Addressing these issues will build more trust with your customers. "
            f"We recommend reviewing these findings at your convenience."
        )
    else:
        return (
            f"Your website {domain} passed our security checks with no significant issues found. "
            f"Your security configuration is well-maintained and follows recommended practices. "
            f"We recommend running regular scans to maintain this level of security."
        )


def _strip_jargon(text: str) -> str:
    """Silently removes banned jargon terms."""
    result = text
    for term in JARGON_BLOCKLIST:
        pattern = re.compile(r'\b' + re.escape(term) + r'\b', re.IGNORECASE)
        result = pattern.sub('', result)
    return re.sub(r'\s+', ' ', result).strip()


def _get_static_fallback(finding: Dict[str, Any]) -> RiskItem:
    """Return deterministic fallback copy for a classified finding, injecting context data."""
    key = finding.get("key", "")
    severity = finding.get("severity", "AMBER")
    check = finding.get("check", "")
    data = finding.get("data", {})

    # Auto-generate count variables for lists in data
    if isinstance(data, dict):
        data_copy = dict(data)
        for k, v in data.items():
            if isinstance(v, list):
                data_copy[f"{k}_count"] = len(v)
    else:
        data_copy = {}

    def _fmt(text: str) -> str:
        try:
            return text.format(**data_copy)
        except Exception:
            return text

    fallback = STATIC_FALLBACKS.get(key)
    if fallback:
        return RiskItem(
            id=hashlib.md5(key.encode()).hexdigest()[:12],
            title=_fmt(fallback[0]),
            severity=severity,
            business_impact=_fmt(fallback[1]),
            technical_detail=_fmt(fallback[2]),
            fix_action=_fmt(fallback[3]),
            confidence=fallback[4],
            fix_difficulty=fallback[5] if len(fallback) > 5 else "Medium",
            estimated_fix_time=fallback[6] if len(fallback) > 6 else "30 minutes",
            check_domain=check,
            check_type=key,
        )
    return RiskItem(
        id=hashlib.md5(key.encode()).hexdigest()[:12],
        title=finding.get("detail", "Security Configuration Issue"),
        severity=severity,
        business_impact="Your website has a security gap that could impact customers.",
        technical_detail=finding.get("detail", "Security misconfiguration detected."),
        fix_action="Consult a web developer to address configuration warnings.",
        confidence="LOW",
        fix_difficulty="Medium",
        estimated_fix_time="30 minutes",
        check_domain=check,
        check_type=key,
    )


async def translate_to_plain_english(classified: List[Dict[str, Any]], domain: str) -> List[RiskItem]:
    """
    Translates technical findings into plain English business risks using Claude AI.
    Now generates business_impact, technical_detail, and fix metadata per finding.
    """
    if not classified:
        return []

    for attempt in range(2):
        try:
            raw_response = await _call_claude(classified, domain)

            # Clean up potential markdown formatting wrapping the JSON
            if raw_response.startswith("```json"):
                raw_response = raw_response.replace("```json\n", "").replace("\n```", "")
            if raw_response.startswith("```"):
                raw_response = raw_response.replace("```\n", "").replace("\n```", "")

            data = json.loads(raw_response)

            results = []
            for idx, item in enumerate(data):
                # Jargon strip on business-facing fields
                item["business_impact"] = _strip_jargon(item.get("business_impact", ""))
                item["fix_action"] = _strip_jargon(item.get("fix_action", ""))
                item["title"] = _strip_jargon(item.get("title", ""))
                # technical_detail MAY contain technical terms

                # Generate ID if not present
                if "id" not in item or not item["id"]:
                    key = classified[idx].get("key", f"finding_{idx}") if idx < len(classified) else f"finding_{idx}"
                    item["id"] = hashlib.md5(key.encode()).hexdigest()[:12]

                # Map check info from classified data
                if idx < len(classified):
                    item.setdefault("check_domain", classified[idx].get("check", ""))
                    item.setdefault("check_type", classified[idx].get("key", ""))

                # Ensure all required fields exist
                item.setdefault("technical_detail", "")
                item.setdefault("fix_difficulty", "Medium")
                item.setdefault("estimated_fix_time", "30 minutes")
                item.setdefault("references", [])

                valid_item = RiskItem(**item)
                results.append(valid_item)

            return results

        except Exception as e:
            logger.error(f"AI translation attempt {attempt + 1} failed: {e}", exc_info=True)
            if attempt == 1:
                break

    # Fallback to static rules
    logger.info("Using static fallbacks for report generation.")
    return [_get_static_fallback(f) for f in classified]


async def generate_executive_summary(classified: List[Dict[str, Any]], domain: str) -> str:
    """Public entry point for executive summary generation."""
    return await _generate_executive_summary(classified, domain)
