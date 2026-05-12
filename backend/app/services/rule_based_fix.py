"""
Rule-based fix generator — produces structured remediation guides
from finding metadata when the Anthropic API is unavailable.
"""

import re
from app.schemas.fix import FixRequest

# Category-specific remediation knowledge base
FIX_KNOWLEDGE: dict[str, dict] = {
    "ssl": {
        "summary": "Your SSL/TLS configuration has security weaknesses that could allow attackers to intercept or downgrade encrypted communications.",
        "impact": "An attacker on the same network can perform man-in-the-middle attacks, intercept credentials, session tokens, and sensitive data transmitted between users and your server.",
        "steps": [
            {"order": 1, "title": "Audit current TLS configuration", "description": "Check which TLS versions and cipher suites your server currently supports.", "code_snippet": "nmap --script ssl-enum-ciphers -p 443 yourdomain.com", "code_language": "bash"},
            {"order": 2, "title": "Disable legacy TLS versions", "description": "Update your web server configuration to only allow TLS 1.2 and TLS 1.3. Remove support for TLS 1.0 and TLS 1.1.", "code_snippet": "# Nginx: /etc/nginx/nginx.conf\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES256-GCM-SHA384';\nssl_prefer_server_ciphers off;", "code_language": "nginx"},
            {"order": 3, "title": "Enable HSTS header", "description": "Add the Strict-Transport-Security header to force browsers to always use HTTPS.", "code_snippet": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;", "code_language": "nginx"},
            {"order": 4, "title": "Verify the fix", "description": "Test your SSL configuration using an online scanner or command line tool.", "code_snippet": "curl -sI https://yourdomain.com | grep -i strict", "code_language": "bash"},
        ],
        "verification": "Run an SSL test to confirm only TLS 1.2+ is supported and the HSTS header is present.",
        "verification_command": "openssl s_client -connect yourdomain.com:443 -tls1 2>/dev/null | head -5",
        "estimated_minutes": 15,
        "difficulty": "easy",
        "references": ["https://wiki.mozilla.org/Security/Server_Side_TLS", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"],
    },
    "headers": {
        "summary": "Your web server is missing critical security headers that protect against common web attacks like clickjacking, XSS, and MIME-type sniffing.",
        "impact": "Without these headers, attackers can embed your site in iframes for clickjacking, exploit cross-site scripting vulnerabilities, and perform MIME-type confusion attacks.",
        "steps": [
            {"order": 1, "title": "Add security headers to your server", "description": "Configure your web server or application to include all recommended security headers in every HTTP response.", "code_snippet": "# Nginx — add to server block\nadd_header X-Content-Type-Options \"nosniff\" always;\nadd_header X-Frame-Options \"DENY\" always;\nadd_header X-XSS-Protection \"1; mode=block\" always;\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\nadd_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'\" always;", "code_language": "nginx"},
            {"order": 2, "title": "Enable HSTS", "description": "Add the Strict-Transport-Security header to enforce HTTPS.", "code_snippet": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;", "code_language": "nginx"},
            {"order": 3, "title": "Verify headers are present", "description": "Check that all security headers are being sent in responses.", "code_snippet": "curl -sI https://yourdomain.com | grep -iE '(x-content|x-frame|strict|referrer|permissions|content-security)'", "code_language": "bash"},
        ],
        "verification": "Use curl or browser DevTools to confirm all security headers appear in the response.",
        "verification_command": "curl -sI https://yourdomain.com | head -20",
        "estimated_minutes": 10,
        "difficulty": "easy",
        "references": ["https://owasp.org/www-project-secure-headers/", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"],
    },
    "dns": {
        "summary": "Your DNS configuration is missing security records that protect your domain from email spoofing and unauthorized certificate issuance.",
        "impact": "Attackers can send phishing emails that appear to come from your domain, and unauthorized SSL certificates can be issued for your domain without your knowledge.",
        "steps": [
            {"order": 1, "title": "Add SPF record", "description": "Create an SPF TXT record to specify which mail servers are authorized to send email for your domain.", "code_snippet": "# DNS TXT Record\nv=spf1 include:_spf.google.com ~all", "code_language": "bash"},
            {"order": 2, "title": "Add DMARC record", "description": "Create a DMARC TXT record to instruct receiving mail servers how to handle unauthorized emails.", "code_snippet": "# DNS TXT Record for _dmarc.yourdomain.com\nv=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com; pct=100", "code_language": "bash"},
            {"order": 3, "title": "Add CAA record", "description": "Restrict which Certificate Authorities can issue SSL certificates for your domain.", "code_snippet": "# DNS CAA Records\n0 issue \"letsencrypt.org\"\n0 issuewild \";\"\n0 iodef \"mailto:security@yourdomain.com\"", "code_language": "bash"},
            {"order": 4, "title": "Verify DNS records", "description": "Use dig or an online tool to verify your new DNS records are propagated.", "code_snippet": "dig TXT yourdomain.com +short\ndig TXT _dmarc.yourdomain.com +short\ndig CAA yourdomain.com +short", "code_language": "bash"},
        ],
        "verification": "Query your DNS records to confirm SPF, DMARC, and CAA are correctly configured.",
        "verification_command": "dig TXT _dmarc.yourdomain.com +short",
        "estimated_minutes": 20,
        "difficulty": "easy",
        "references": ["https://dmarc.org/overview/", "https://letsencrypt.org/docs/caa/"],
    },
    "ports": {
        "summary": "Your server has unnecessary network ports exposed to the public internet, increasing your attack surface significantly.",
        "impact": "Exposed database or admin ports allow attackers to directly connect to internal services, attempt brute-force attacks, or exploit known vulnerabilities in those services.",
        "steps": [
            {"order": 1, "title": "Identify all open ports", "description": "Scan your server to identify which ports are currently exposed.", "code_snippet": "nmap -sV -p 1-65535 yourdomain.com", "code_language": "bash"},
            {"order": 2, "title": "Configure firewall rules", "description": "Block all unnecessary ports using your cloud provider's security groups or a host-based firewall. Only allow ports 80, 443, and SSH (22) from trusted IPs.", "code_snippet": "# UFW (Ubuntu)\nsudo ufw default deny incoming\nsudo ufw allow 80/tcp\nsudo ufw allow 443/tcp\nsudo ufw allow from YOUR_IP to any port 22\nsudo ufw enable", "code_language": "bash"},
            {"order": 3, "title": "Move databases behind VPN", "description": "Ensure database ports (3306, 5432, 27017, 6379) are only accessible from your application servers, never from the public internet.", "code_snippet": "# AWS Security Group — remove 0.0.0.0/0 from DB ports\naws ec2 revoke-security-group-ingress \\\n  --group-id sg-xxxx \\\n  --protocol tcp --port 5432 \\\n  --cidr 0.0.0.0/0", "code_language": "bash"},
            {"order": 4, "title": "Verify ports are closed", "description": "Re-scan to confirm only required ports remain open.", "code_snippet": "nmap -p 3306,5432,27017,6379 yourdomain.com", "code_language": "bash"},
        ],
        "verification": "Run a port scan to confirm database and admin ports are no longer accessible from the public internet.",
        "verification_command": "nmap -p 3306,5432,27017,6379,8080 yourdomain.com",
        "estimated_minutes": 30,
        "difficulty": "medium",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"],
    },
    "cookies": {
        "summary": "Your application's cookies are missing security flags, making them vulnerable to theft via XSS attacks or interception over unencrypted connections.",
        "impact": "An attacker can steal session cookies through cross-site scripting or network interception, gaining unauthorized access to user accounts.",
        "steps": [
            {"order": 1, "title": "Set HttpOnly flag", "description": "Add the HttpOnly flag to all session and authentication cookies to prevent JavaScript access.", "code_snippet": "Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/", "code_language": "bash"},
            {"order": 2, "title": "Set Secure flag", "description": "Add the Secure flag to ensure cookies are only sent over HTTPS connections.", "code_snippet": "# Express.js example\nres.cookie('session', token, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'strict',\n  maxAge: 3600000\n});", "code_language": "javascript"},
            {"order": 3, "title": "Set SameSite attribute", "description": "Add SameSite=Strict or SameSite=Lax to prevent CSRF attacks.", "code_snippet": None, "code_language": None},
            {"order": 4, "title": "Verify cookie flags", "description": "Check cookies in browser DevTools or via curl.", "code_snippet": "curl -sI https://yourdomain.com/login | grep -i set-cookie", "code_language": "bash"},
        ],
        "verification": "Check the Set-Cookie headers in your application responses to confirm all security flags are present.",
        "verification_command": "curl -sI https://yourdomain.com | grep -i set-cookie",
        "estimated_minutes": 10,
        "difficulty": "easy",
        "references": ["https://owasp.org/www-community/controls/SecureCookieAttribute", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"],
    },
    "cors": {
        "summary": "Your CORS configuration allows requests from any origin, which can be exploited to make authenticated cross-origin requests on behalf of your users.",
        "impact": "An attacker can create a malicious website that makes API requests to your server using your users' credentials, stealing sensitive data or performing unauthorized actions.",
        "steps": [
            {"order": 1, "title": "Replace wildcard with allowlist", "description": "Replace Access-Control-Allow-Origin: * with an explicit list of trusted origins.", "code_snippet": "# Nginx\nmap $http_origin $cors_origin {\n    default '';\n    'https://yourdomain.com' $http_origin;\n    'https://app.yourdomain.com' $http_origin;\n}\nadd_header Access-Control-Allow-Origin $cors_origin always;", "code_language": "nginx"},
            {"order": 2, "title": "Restrict allowed methods and headers", "description": "Only allow the HTTP methods and headers your API actually needs.", "code_snippet": "add_header Access-Control-Allow-Methods 'GET, POST, PUT, DELETE' always;\nadd_header Access-Control-Allow-Headers 'Authorization, Content-Type' always;", "code_language": "nginx"},
            {"order": 3, "title": "Never use credentials with wildcard", "description": "If you need Access-Control-Allow-Credentials: true, you must specify exact origins, never use wildcard.", "code_snippet": None, "code_language": None},
            {"order": 4, "title": "Test CORS configuration", "description": "Verify that unauthorized origins are rejected.", "code_snippet": "curl -H 'Origin: https://evil.com' -sI https://yourdomain.com/api | grep -i access-control", "code_language": "bash"},
        ],
        "verification": "Make a request with an unauthorized Origin header and confirm it is rejected.",
        "verification_command": "curl -H 'Origin: https://evil.com' -sI https://api.yourdomain.com | grep -i access-control",
        "estimated_minutes": 15,
        "difficulty": "easy",
        "references": ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
    },
    "cloud_storage": {
        "summary": "A cloud storage bucket associated with your domain is publicly accessible, potentially exposing sensitive files, backups, or configuration data.",
        "impact": "Attackers can download sensitive data including database backups, user data, credentials, and internal documents from the exposed bucket.",
        "steps": [
            {"order": 1, "title": "Identify the exposed bucket", "description": "Determine which cloud storage buckets are publicly accessible and what data they contain.", "code_snippet": "# AWS S3\naws s3 ls s3://your-bucket-name --no-sign-request", "code_language": "bash"},
            {"order": 2, "title": "Remove public access", "description": "Block all public access to the bucket immediately.", "code_snippet": "# AWS S3 — block public access\naws s3api put-public-access-block \\\n  --bucket your-bucket-name \\\n  --public-access-block-configuration \\\n  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", "code_language": "bash"},
            {"order": 3, "title": "Audit bucket contents", "description": "Review all files in the bucket. If sensitive data was exposed, treat this as a data breach.", "code_snippet": None, "code_language": None},
            {"order": 4, "title": "Enable bucket logging", "description": "Turn on access logging to detect any unauthorized access that may have occurred.", "code_snippet": None, "code_language": None},
        ],
        "verification": "Attempt to access the bucket without authentication to confirm public access is blocked.",
        "verification_command": "aws s3 ls s3://your-bucket-name --no-sign-request 2>&1 | head -3",
        "estimated_minutes": 15,
        "difficulty": "easy",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/11-Test_Cloud_Storage"],
    },
    "cms": {
        "summary": "Your content management system has security vulnerabilities that could allow attackers to compromise your website.",
        "impact": "Attackers can exploit CMS vulnerabilities to inject malicious code, deface your website, steal user data, or use your server for further attacks.",
        "steps": [
            {"order": 1, "title": "Update CMS to latest version", "description": "Apply all available security patches and update to the latest stable version of your CMS.", "code_snippet": "# WordPress\nwp core update\nwp plugin update --all\nwp theme update --all", "code_language": "bash"},
            {"order": 2, "title": "Remove unused plugins and themes", "description": "Deactivate and delete any plugins or themes that are not actively used — they are attack vectors even when inactive.", "code_snippet": None, "code_language": None},
            {"order": 3, "title": "Harden admin access", "description": "Change the default admin URL, enforce strong passwords, and enable two-factor authentication.", "code_snippet": None, "code_language": None},
            {"order": 4, "title": "Verify updates are applied", "description": "Check your CMS version and scan for remaining vulnerabilities.", "code_snippet": "wp core version\nwp plugin list --fields=name,version,update_version", "code_language": "bash"},
        ],
        "verification": "Confirm your CMS is running the latest version with all plugins updated.",
        "verification_command": None,
        "estimated_minutes": 30,
        "difficulty": "medium",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
}

# Default fallback for unknown categories
DEFAULT_FIX: dict = {
    "summary": "A security misconfiguration or vulnerability was detected on your server that should be addressed to reduce your attack surface.",
    "impact": "If left unresolved, this issue could be exploited by attackers to gain unauthorized access, steal data, or disrupt your service.",
    "steps": [
        {"order": 1, "title": "Review the finding details", "description": "Examine the technical detail provided in the scan report to understand the exact nature of this vulnerability.", "code_snippet": None, "code_language": None},
        {"order": 2, "title": "Research the remediation", "description": "Look up the specific vulnerability in the OWASP Testing Guide or CWE database for detailed remediation guidance.", "code_snippet": None, "code_language": None},
        {"order": 3, "title": "Apply the fix", "description": "Implement the recommended configuration change or code fix based on the finding's fix_action field.", "code_snippet": None, "code_language": None},
        {"order": 4, "title": "Verify and re-scan", "description": "After applying the fix, run another scan to confirm the vulnerability is resolved.", "code_snippet": None, "code_language": None},
    ],
    "verification": "Re-scan the target to confirm this finding no longer appears in the report.",
    "verification_command": None,
    "estimated_minutes": 20,
    "difficulty": "medium",
    "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
}

DIFFICULTY_MAP = {"critical": "hard", "high": "medium", "medium": "medium", "low": "easy"}
TIME_MAP = {"critical": 30, "high": 20, "medium": 15, "low": 10}


def generate_rule_based_fix(req: FixRequest) -> dict:
    """Generate a structured fix response from the rule-based knowledge base."""
    cat = req.category.lower().strip()
    base = FIX_KNOWLEDGE.get(cat, DEFAULT_FIX).copy()

    # Enrich summary with finding-specific context
    title = req.finding_title
    desc = req.finding_description
    detail = req.finding_detail

    if desc and desc != title:
        base["summary"] = f"{title}: {desc}"
    if detail and detail != desc:
        base["impact"] = detail

    # Override difficulty/time based on severity
    sev = req.severity.lower()
    base["difficulty"] = DIFFICULTY_MAP.get(sev, base.get("difficulty", "medium"))
    base["estimated_minutes"] = TIME_MAP.get(sev, base.get("estimated_minutes", 15))

    # Ensure steps list is properly formatted
    steps = base.get("steps", DEFAULT_FIX["steps"])
    base["steps"] = [
        {
            "order": s.get("order", i + 1),
            "title": s.get("title", f"Step {i + 1}"),
            "description": s.get("description", ""),
            "code_snippet": s.get("code_snippet"),
            "code_language": s.get("code_language"),
        }
        for i, s in enumerate(steps)
    ]

    return {
        "summary": base["summary"],
        "impact": base["impact"],
        "steps": base["steps"],
        "verification": base.get("verification", "Re-scan the target to confirm this finding is resolved."),
        "verification_command": base.get("verification_command"),
        "estimated_minutes": base["estimated_minutes"],
        "difficulty": base["difficulty"],
        "references": base.get("references", []),
    }
