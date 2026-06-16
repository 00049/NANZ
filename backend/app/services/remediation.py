"""
Remediation Roadmap Engine v2 — NANZ Platform

Calculates impact-to-effort (ROI) ratios using the new R-score formula,
groups findings into phased roadmap, and generates stack-specific code fixes.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity weights for ROI calculation
# ---------------------------------------------------------------------------
SEVERITY_WEIGHTS: dict[str, int] = {
    "CRITICAL": 100,
    "HIGH": 75,
    "RED": 75,
    "MEDIUM": 50,
    "AMBER": 50,
    "LOW": 25,
    "GREEN": 0,
    "INFO": 10,
}

EFFORT_SCORES: dict[str, int] = {"Easy": 1, "Medium": 3, "Hard": 5, "Complex": 8}

# Approximate score reduction (points out of 100) if this finding is fixed
SCORE_DELTA: dict[str, int] = {
    "CRITICAL": 15,
    "RED": 8,
    "HIGH": 8,
    "AMBER": 4,
    "MEDIUM": 4,
    "LOW": 1,
    "GREEN": 0,
    "INFO": 0,
}

# Compliance violations resolved when a finding_key is fixed
REGULATORY_IMPACT: dict[str, list[str]] = {
    "ssl_invalid": ["GDPR Art.32", "DPDP S.8(4)", "PCI DSS Req.4.2.1", "SOC2 CC6.7"],
    "ssl_tls10_supported": ["PCI DSS Req.4.2.1 (TLS 1.0 prohibited)", "GDPR Art.32"],
    "ssl_tls11_supported": ["PCI DSS Req.4.2.1 (TLS 1.1 prohibited)", "GDPR Art.32"],
    "ssl_heartbleed": ["GDPR Art.32", "PCI DSS Req.6.3.3", "DORA Art.10"],
    "headers_no_https_redirect": ["GDPR Art.32", "DPDP S.8(4)", "PCI DSS Req.4.2.1"],
    "headers_many_missing": ["GDPR Art.25", "PCI DSS Req.6.4.1", "SOC2 CC6.6"],
    "dns_no_email_protection": ["GDPR Art.32", "DPDP S.8(4)", "PCI DSS Req.5.4.1"],
    "dns_no_spf": ["GDPR Art.32", "PCI DSS Req.5.4.1"],
    "dns_no_dmarc": ["GDPR Art.32", "PCI DSS Req.5.4.1"],
    "dns_no_dnssec": ["DORA Art.9(2)", "SOC2 CC6.6"],
    "dns_no_caa": ["PCI DSS Req.4.2.1"],
    "dns_zone_transfer": ["PCI DSS Req.1.3.2", "DORA Art.9(2)", "SOC2 CC6.6"],
    "ports_database_exposed": [
        "DPDP S.8(4)",
        "GDPR Art.32",
        "PCI DSS Req.1.3.2",
        "SOC2 CC6.1",
        "DORA Art.9(2)",
    ],
    "dangerous_ports_exposed": ["PCI DSS Req.1.3.2", "SOC2 CC6.6", "DORA Art.9(2)"],
    "webapp_exposed_.env": [
        "GDPR Art.32+33",
        "DPDP S.8(4)",
        "PCI DSS Req.3.4.1",
        "SOC2 CC6.1",
    ],
    "webapp_exposed_.git_config": ["PCI DSS Req.6.3.1", "SOC2 CC6.6"],
    "cors_wildcard_api": ["GDPR Art.25", "PCI DSS Req.6.4.1"],
    "cors_credentials_wildcard": ["GDPR Art.32", "PCI DSS Req.6.4.1"],
    "public_cloud_bucket": [
        "DPDP S.8(4)",
        "GDPR Art.32+33",
        "PCI DSS Req.1.3.2",
        "SOC2 CC6.1",
    ],
    "cookie_missing_httponly": ["GDPR Art.32", "PCI DSS Req.6.4.1"],
    "cookie_missing_secure": ["GDPR Art.32", "PCI DSS Req.4.2.1"],
    "cookie_missing_samesite": ["GDPR Art.25"],
    "source_map_exposed": ["PCI DSS Req.6.3.1", "SOC2 CC6.6"],
    "mixed_content_detected": ["GDPR Art.32", "PCI DSS Req.4.2.1"],
    "trace_enabled": ["PCI DSS Req.6.4.1", "SOC2 CC6.6"],
}

# ---------------------------------------------------------------------------
# Stack-specific code fix snippets
# ---------------------------------------------------------------------------

CODE_FIXES: dict[str, dict[str, str]] = {
    "headers_many_missing": {
        "django": """# settings.py — add django-csp and django-secure
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'csp.middleware.CSPMiddleware',
    ...
]
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
CSP_DEFAULT_SRC = ("'self'",)
PERMISSIONS_POLICY = {'camera': [], 'microphone': []}
""",
        "express": """// app.js — install helmet: npm install helmet
const helmet = require('helmet');
app.use(helmet());
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
app.use(helmet.contentSecurityPolicy({
  directives: { defaultSrc: ["'self'"] }
}));
""",
        "laravel": """// app/Http/Middleware/SecurityHeaders.php
public function handle($request, Closure $next) {
    $response = $next($request);
    $response->headers->set('X-Content-Type-Options', 'nosniff');
    $response->headers->set('X-Frame-Options', 'DENY');
    $response->headers->set('Strict-Transport-Security', 'max-age=31536000');
    $response->headers->set('Content-Security-Policy', "default-src 'self'");
    return $response;
}
""",
        "spring": """// SecurityConfig.java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.headers(headers -> headers
        .frameOptions(frame -> frame.deny())
        .contentTypeOptions(Customizer.withDefaults())
        .httpStrictTransportSecurity(hsts -> hsts
            .includeSubDomains(true)
            .maxAgeInSeconds(31536000))
    );
    return http.build();
}
""",
        "fastapi": """# main.py — install secure: pip install secure
from secure import Secure
secure_headers = Secure()

@app.middleware("http")
async def set_secure_headers(request, call_next):
    response = await call_next(request)
    secure_headers.framework.fastapi(response)
    return response
""",
        "default": "Add the following HTTP response headers to your server configuration:\n- Strict-Transport-Security: max-age=31536000; includeSubDomains\n- Content-Security-Policy: default-src 'self'\n- X-Frame-Options: DENY\n- X-Content-Type-Options: nosniff\n- Referrer-Policy: strict-origin-when-cross-origin\n- Permissions-Policy: camera=(), microphone=()",
    },
    "cors_wildcard_api": {
        "django": """# settings.py — install django-cors-headers
CORS_ALLOWED_ORIGINS = [
    "https://yourdomain.com",
    "https://app.yourdomain.com",
]
# Remove: CORS_ALLOW_ALL_ORIGINS = True
""",
        "express": """// Replace wildcard CORS with explicit allowlist
const cors = require('cors');
app.use(cors({
  origin: ['https://yourdomain.com', 'https://app.yourdomain.com'],
  credentials: true,
}));
""",
        "fastapi": """# main.py
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
""",
        "default": "Replace 'Access-Control-Allow-Origin: *' with an explicit allowlist of trusted domains. Never use wildcard with allow_credentials=true.",
    },
    "cookie_missing_httponly": {
        "django": """# settings.py
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True   # also fix cookie_missing_secure
SESSION_COOKIE_SAMESITE = 'Strict'
""",
        "express": """// Use cookie options
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'Strict',
  maxAge: 3600000
});
""",
        "laravel": """// config/session.php
'http_only' => true,
'secure'    => env('SESSION_SECURE_COOKIE', true),
'same_site' => 'strict',
""",
        "default": "Set the HttpOnly, Secure, and SameSite=Strict flags on all session and authentication cookies.",
    },
    "dns_no_dmarc": {
        "default": """Add the following DNS TXT record for your domain:
Name:  _dmarc.yourdomain.com
Value: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; ruf=mailto:dmarc@yourdomain.com; pct=100

Start with p=quarantine if you want to monitor first, then switch to p=reject.
Also add SPF:  v=spf1 include:_spf.yourmailprovider.com ~all
""",
    },
    "dns_no_caa": {
        "default": """Add CAA records to restrict which CAs can issue certificates for your domain:
0 issue "letsencrypt.org"    ; Allow Let's Encrypt
0 issue "digicert.com"       ; Allow DigiCert (if used)
0 issuewild ";"              ; Disallow all wildcard certs
0 iodef "mailto:security@yourdomain.com"  ; Report violations
""",
    },
    "ssl_tls10_supported": {
        "nginx": """# /etc/nginx/nginx.conf
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers off;
""",
        "apache": """# /etc/apache2/sites-available/ssl.conf
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!DES
""",
        "default": "Disable TLS 1.0 and 1.1 in your web server or load balancer configuration. Only allow TLS 1.2 and TLS 1.3.",
    },
    "source_map_exposed": {
        "webpack": """// webpack.config.js — disable source maps in production
module.exports = {
  devtool: process.env.NODE_ENV === 'production' ? false : 'eval-source-map',
};
""",
        "nextjs": """// next.config.js
module.exports = {
  productionBrowserSourceMaps: false,
};
""",
        "default": "Disable source map generation for your production build. In webpack, set devtool: false for production. In Next.js, set productionBrowserSourceMaps: false.",
    },
    "webapp_exposed_.env": {
        "nginx": """# Deny access to .env and hidden files in nginx
location ~ /\\. {
    deny all;
    return 404;
}
location ~* \\.(env|git|bak|sql|log)$ {
    deny all;
    return 404;
}
""",
        "apache": """# .htaccess — deny sensitive files
<FilesMatch "\\.(env|git|bak|sql|log|config)$">
    Order allow,deny
    Deny from all
</FilesMatch>
""",
        "default": "Block access to .env, .git, and configuration files at the web server level. Immediately rotate all credentials found in the exposed file.",
    },
    "trace_enabled": {
        "nginx": "# Disable TRACE in nginx:\nlocation / { limit_except GET POST HEAD DELETE PUT PATCH OPTIONS { deny all; } }",
        "apache": "# Disable TRACE in apache:\nTraceEnable off",
        "default": "Disable the HTTP TRACE method in your web server configuration to prevent Cross-Site Tracing (XST) attacks.",
    },
}

# ---------------------------------------------------------------------------
# Framework detection from tech inventory
# ---------------------------------------------------------------------------


def detect_backend_framework(domain_report: dict) -> str:
    """
    Detect the target's backend framework from the tech inventory / domain reports.
    Returns a lowercase framework key: 'django', 'express', 'laravel', 'spring',
    'fastapi', 'flask', 'rails', 'nginx', 'apache', or 'default'.
    """
    tech_data = domain_report.get("tech", {}) or {}
    technologies = tech_data.get("technologies", [])
    cms_data = domain_report.get("cms", {}) or {}
    headers_data = domain_report.get("headers", {}) or {}

    # Flatten all tech names
    tech_names = [
        str(t.get("name", "")).lower() for t in technologies if isinstance(t, dict)
    ]
    server_header = str(headers_data.get("server_header", "")).lower()
    x_powered_by = str(headers_data.get("x_powered_by", "")).lower()
    cms_name = str(cms_data.get("cms_detected", "")).lower()

    all_signals = " ".join(tech_names + [server_header, x_powered_by, cms_name])

    if "django" in all_signals:
        return "django"
    if (
        "fastapi" in all_signals
        or "uvicorn" in all_signals
        or "starlette" in all_signals
    ):
        return "fastapi"
    if "flask" in all_signals or "werkzeug" in all_signals:
        return "flask"
    if "laravel" in all_signals or "php" in all_signals:
        return "laravel"
    if "spring" in all_signals or "tomcat" in all_signals or "java" in all_signals:
        return "spring"
    if "express" in all_signals or "node" in all_signals:
        return "express"
    if "rails" in all_signals or "ruby" in all_signals:
        return "rails"
    if "nginx" in server_header:
        return "nginx"
    if "apache" in server_header:
        return "apache"

    return "default"


def generate_code_fix(finding_key: str, framework: str) -> str:
    """Return a language/framework-specific remediation snippet for a finding."""
    fixes_for_key = CODE_FIXES.get(finding_key, {})
    if not fixes_for_key:
        return ""
    return fixes_for_key.get(framework) or fixes_for_key.get("default", "")


# ---------------------------------------------------------------------------
# Main roadmap generator
# ---------------------------------------------------------------------------


def generate_roadmap(
    findings: list[dict[str, Any]],
    framework: str = "default",
) -> dict[str, Any]:
    """
    Generate a prioritized remediation roadmap.

    Findings are sorted by impact-to-effort ROI (using the R-score when
    available, otherwise falling back to severity/effort). Each item gets:
      - roi_score
      - risk_score_reduction_delta  (estimated score improvement after fix)
      - regulatory_impact           (list of compliance clauses resolved)
      - code_fix                    (stack-specific snippet)
    """
    prioritized = []

    for finding in findings:
        severity = finding.get("severity", "INFO")
        difficulty = finding.get("fix_difficulty", "Medium")
        key = finding.get("check_type") or finding.get("key") or ""

        # Use pre-computed R-score from orchestrator if available
        r_score = finding.get("risk_score")
        if r_score is None:
            impact = SEVERITY_WEIGHTS.get(severity, 10)
            effort = EFFORT_SCORES.get(difficulty, 3)
            r_score = impact / effort if effort > 0 else impact

        item = dict(finding)
        item["roi_score"] = round(r_score, 2)
        item["risk_score_reduction_delta"] = SCORE_DELTA.get(severity, 0)
        item["regulatory_impact"] = REGULATORY_IMPACT.get(key, [])
        item["code_fix"] = generate_code_fix(key, framework)
        prioritized.append(item)

    # Sort by highest ROI (best bang-for-buck first)
    prioritized.sort(key=lambda x: x["roi_score"], reverse=True)

    # Group into 3 phases
    phase_1: list[dict] = []  # Immediate: Critical/High or Easy quick-wins
    phase_2: list[dict] = []  # Short-term: Medium/Amber
    phase_3: list[dict] = []  # Long-term: Low/Info or Complex

    for item in prioritized:
        sev = item.get("severity", "INFO")
        diff = item.get("fix_difficulty", "Medium")
        score = item.get("roi_score", 0)

        if sev in ("CRITICAL", "HIGH", "RED") or (diff == "Easy" and score >= 20):
            phase_1.append(item)
        elif sev in ("MEDIUM", "AMBER"):
            phase_2.append(item)
        else:
            phase_3.append(item)

    total_delta = sum(i.get("risk_score_reduction_delta", 0) for i in prioritized)

    return {
        "phases": {
            "phase_1_immediate": phase_1,
            "phase_2_short_term": phase_2,
            "phase_3_long_term": phase_3,
        },
        "total_items": len(prioritized),
        "estimated_score_gain": min(total_delta, 60),  # capped at realistic max
        "detected_framework": framework,
    }
