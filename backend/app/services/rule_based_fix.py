"""
Rule-based fix generator — produces structured remediation guides
from finding metadata when the Anthropic/OpenAI API is unavailable.
"""

import re
from app.schemas.fix import FixRequest

# Category-specific remediation knowledge base
FIX_KNOWLEDGE: dict[str, dict] = {
    # ── Legacy Categories ──
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

    # ── Enterprise Intelligence Base ──
    "sqli": {
        "summary": "SQL Injection (SQLi) occurs when an application inadvertently concatenates untrusted input directly into an executable SQL statement, allowing attackers to alter the syntactic structure of the query.",
        "impact": "Complete compromise of confidentiality, integrity, and availability. Attackers can extract sensitive database tables, modify financial records, or exploit administrative procedures (e.g., xp_cmdshell) to execute arbitrary commands on the underlying host OS.",
        "steps": [
            {"order": 1, "title": "Eradicate Raw String Concatenation", "description": "Immediately refactor any codebase using string interpolation (e.g., Python f-strings) or direct concatenation for database queries.", "code_snippet": None, "code_language": None},
            {"order": 2, "title": "Implement Parameterized Queries", "description": "Ensure the database driver treats user input strictly as literal values by utilizing parameterized queries (e.g., $1 variables in Postgres) or native ORM features.", "code_snippet": "/* Node.js (pg) Example */\nconst query = \"SELECT * FROM accounts WHERE id = $1\";\nconst result = await client.query(query, [userId]);", "code_language": "javascript"},
            {"order": 3, "title": "Deploy WAF Protection", "description": "Deploy Web Application Firewall rules utilizing complex regular expressions (e.g., `(?i)(\\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\\b)`) to intercept malicious payloads at the edge.", "code_snippet": None, "code_language": None},
        ],
        "verification": "Utilize safe, boolean inferential payloads (e.g., `?id=1' AND 1=1--` vs `?id=1' AND 1=2--`) to confirm the database no longer evaluates the injected logical operators.",
        "verification_command": "curl -s \"https://yourdomain.com/api/data?id=1' AND 1=1--\"",
        "estimated_minutes": 30,
        "difficulty": "medium",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    },
    "xss": {
        "summary": "Cross-Site Scripting (XSS) manifests when a web application processes untrusted user input and reflects or stores it within an HTML response without applying rigorous, context-aware output encoding.",
        "impact": "Attackers can inject malicious executable JavaScript into the victim's browser context, enabling session hijacking, unauthorized data exfiltration, account impersonation, and client-side malware deployment.",
        "steps": [
            {"order": 1, "title": "Enforce Context-Aware Output Encoding", "description": "Eliminate framework escape hatches (e.g., React's `dangerouslySetInnerHTML`, Laravel's `{!! !!}`, Django's `|safe` filter). Force all variables through default auto-escaping rendering engines.", "code_snippet": "<!-- Django Secure Example -->\n<div class=\"bio\">{{ user.biography }}</div>", "code_language": "html"},
            {"order": 2, "title": "Sanitize Required Rich Text", "description": "If users must submit HTML (e.g., WYSIWYG editors), meticulously strip dangerous tags and event handlers (onerror, onload) using an industry-standard library like DOMPurify prior to database storage.", "code_snippet": "const cleanHTML = DOMPurify.sanitize(dirtyInput);", "code_language": "javascript"},
            {"order": 3, "title": "Deploy Content Security Policy (CSP)", "description": "Implement strict CSP headers to explicitly block the execution of unauthorized inline scripts.", "code_snippet": "Content-Security-Policy: default-src 'self'; script-src 'self'", "code_language": "http"},
            {"order": 4, "title": "Set HttpOnly Cookie Flags", "description": "Prevent JavaScript access to session tokens to mitigate the operational impact of a successful XSS payload.", "code_snippet": "Set-Cookie: session=xyz; HttpOnly; Secure; SameSite=Strict", "code_language": "http"},
        ],
        "verification": "Submit benign HTML tags (e.g., `<h1>test</h1>` or `<script>alert(1)</script>`) into input fields and verify the response safely renders the literal text via HTML entities (&lt;h1&gt;) instead of executing it.",
        "verification_command": None,
        "estimated_minutes": 25,
        "difficulty": "medium",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
    },
    "csrf": {
        "summary": "Cross-Site Request Forgery (CSRF) capitalizes on the browser's default behavior of automatically appending ambient session cookies to cross-origin requests, coercing an authenticated victim into executing unauthorized state-changing actions.",
        "impact": "Attackers can silently alter user account details, modify administrative configurations, or initiate unauthorized financial transactions using the victim's authenticated session.",
        "steps": [
            {"order": 1, "title": "Configure SameSite Cookie Attributes", "description": "Instruct the client browser to never transmit session cookies during cross-site requests by setting the SameSite attribute.", "code_snippet": "Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Lax", "code_language": "http"},
            {"order": 2, "title": "Implement Anti-CSRF Tokens", "description": "Require an unpredictable, server-generated validation token for all state-changing endpoints (POST, PUT, DELETE). Ensure middleware (e.g., csurf in Node, CsrfViewMiddleware in Django) is universally applied.", "code_snippet": "<!-- Laravel Example -->\n<form method=\"POST\" action=\"/update\">\n    @csrf\n    <button type=\"submit\">Save</button>\n</form>", "code_language": "html"},
            {"order": 3, "title": "Enforce Custom Headers for SPAs", "description": "For API-driven Single Page Applications relying on CORS, mandate a custom HTTP header (e.g., `X-Requested-With: XMLHttpRequest`) which standard browsers block on cross-origin requests without explicit permission.", "code_snippet": None, "code_language": None},
        ],
        "verification": "Using an intercepting proxy (like Burp Suite), capture a state-changing POST request, strip the Anti-CSRF token parameter, and submit it. Ensure the server forcefully rejects it with a 403 Forbidden.",
        "verification_command": None,
        "estimated_minutes": 20,
        "difficulty": "medium",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
    },
    "idor": {
        "summary": "Insecure Direct Object Reference (IDOR) / Broken Access Control occurs when an application exposes internal object identifiers (like sequential integers) to the client but fails to enforce rigorous authorization checks upon receiving them.",
        "impact": "Enables horizontal privilege escalation (accessing peer user data) and vertical privilege escalation (manipulating administrative records), leading to massive data exposure and compliance violations.",
        "steps": [
            {"order": 1, "title": "Implement Indirect Object References", "description": "Replace predictable, sequential auto-incrementing integers in client-facing APIs with cryptographically secure, unguessable identifiers (e.g., UUIDv4).", "code_snippet": None, "code_language": None},
            {"order": 2, "title": "Enforce Object-Level Authorization", "description": "Ensure every data retrieval and manipulation function validates the requester's authenticated session against the target object's ownership metadata.", "code_snippet": "/* Express.js Secure Example */\nif (req.user.id !== requestedObject.ownerId && req.user.role !== 'ADMIN') {\n    return res.status(403).json({ error: \"Unauthorized\" });\n}", "code_language": "javascript"},
            {"order": 3, "title": "Utilize Framework Access Controls", "description": "Leverage centralized authorization frameworks such as Spring Security @PreAuthorize annotations, Laravel Policies, or Django object-level permissions to ensure rules are consistently applied.", "code_snippet": "/* Spring Boot Secure Example */\n@PreAuthorize(\"@securityService.isOwner(authentication, #id)\")\npublic Order getOrder(@PathVariable Long id) { ... }", "code_language": "java"},
        ],
        "verification": "Authenticate as User A, intercept an API request, capture an object identifier (e.g., ?invoice_id=100), then authenticate as User B and attempt to access that exact identifier. Verify the server returns a 403 Forbidden.",
        "verification_command": None,
        "estimated_minutes": 45,
        "difficulty": "hard",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"],
    },
    "path_traversal": {
        "summary": "Path Traversal (Directory Traversal) occurs when an application accepts user-supplied input to construct a file path and passes it to OS filesystem APIs without adequate normalization or boundary validation.",
        "impact": "Catastrophic exposure of highly sensitive system assets including password hashes (/etc/passwd), source code, private SSH keys, and configuration files containing database credentials (.env files).",
        "steps": [
            {"order": 1, "title": "Implement Indirect File Mapping", "description": "Never reference local filesystem paths directly via user input. Store a cryptographic hash or UUID in the database that acts as a secure, non-traversable proxy linking to the actual file path.", "code_snippet": None, "code_language": None},
            {"order": 2, "title": "Strip Traversal Sequences", "description": "If dynamic file handling is strictly unavoidable, utilize language-specific functions to aggressively discard directory traversal characters (e.g., ../ or ..\\).", "code_snippet": "/* PHP Secure Example */\n$filename = basename($_GET['file']);", "code_language": "php"},
            {"order": 3, "title": "Enforce Canonicalization and Boundary Checks", "description": "Resolve the user input into a canonical absolute path (resolving symbolic links and relative sequences), then strictly verify the resulting path begins explicitly with the designated upload/storage root directory.", "code_snippet": "/* Node.js Secure Example */\nconst resolvedPath = path.resolve(rootDir, filename);\nif (!resolvedPath.startsWith(rootDir + path.sep)) {\n    throw new Error('Path traversal attempt');\n}", "code_language": "javascript"},
        ],
        "verification": "Attempt to access file endpoints using deep traversal sequences (e.g., ?file=../../../../../../etc/passwd) and double-URL encoded variants (%252e%252e%252f). Confirm the application securely rejects the payload.",
        "verification_command": "curl -s \"https://yourdomain.com/download?file=../../../../../../etc/passwd\"",
        "estimated_minutes": 35,
        "difficulty": "medium",
        "references": ["https://portswigger.net/web-security/file-path-traversal"],
    },
}

# Aliases for category mapping
CATEGORY_ALIASES = {
    "sql_injection": "sqli",
    "broken_access_control": "idor",
    "directory_traversal": "path_traversal",
    "webapp": "xss", # generic mapping for webapp vulnerabilities if specific type isn't known
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
    
    # Resolve aliases
    cat = CATEGORY_ALIASES.get(cat, cat)
    
    # Fallback to fuzzy match if exact match fails
    matched_cat = None
    if cat in FIX_KNOWLEDGE:
        matched_cat = cat
    else:
        for known_cat in FIX_KNOWLEDGE.keys():
            if known_cat in cat or cat in known_cat:
                matched_cat = known_cat
                break
                
    base = FIX_KNOWLEDGE.get(matched_cat, DEFAULT_FIX).copy() if matched_cat else DEFAULT_FIX.copy()

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
