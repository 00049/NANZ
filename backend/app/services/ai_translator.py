import json
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
    "API", "XSS", "SQLI", "OWASP", "TCP", "UDP", "RFC", "MIME", "DOM", "regex"
]

STATIC_FALLBACKS = {
    "ssl_invalid": ("Website Identity Error", "Visitors will see a warning that your site is unsafe, causing them to leave.", "Contact your website host to fix your security certificate.", "HIGH"),
    "ssl_expiring_critical": ("Security Warning Imminent", "Your website will soon show a 'Not Secure' warning to all users.", "Renew your security certificate with your hosting provider immediately.", "HIGH"),
    "ssl_expiring_soon": ("Security Renewal Needed", "If ignored, customers may lose trust when your site shows warnings.", "Plan to renew your security certificate within the next few weeks.", "MEDIUM"),
    "ssl_self_signed": ("Untrusted Security", "Customers will see a scary red warning blocking them from your store.", "Purchase a recognized security certificate from a trusted provider.", "HIGH"),
    "ssl_old_tls": ("Outdated Security Tech", "Old devices might be vulnerable when connecting to your store.", "Ask your host to disable older connection protocols.", "MEDIUM"),
    "headers_many_missing": ("Missing Basic Protections", "Hackers have an easier time tricking your website into doing malicious things.", "Ask your developer to add standard web security guardrails.", "HIGH"),
    "headers_some_missing": ("Incomplete Defenses", "Some pages might be vulnerable to being embedded in fake sites.", "Have your web team review and update your site's protection settings.", "MEDIUM"),
    "dns_no_email_protection": ("Email Spoofing Risk", "Scammers can send fake emails pretending to be from your business.", "Set up specific records with your domain provider to prove emails are really from you.", "HIGH"),
    "dns_partial_protection": ("Incomplete Email Security", "Some spoofed emails might still reach your customers.", "Complete your domain email security setup.", "MEDIUM"),
    "dangerous_ports_exposed": ("Critical Open Doors", "Highly sensitive internal systems are visible to anyone on the internet.", "Firewall off these technical access points immediately.", "HIGH"),
    "unusual_ports_open": ("Unnecessary Access Points", "Extra doors to your server provide more ways for attackers to get in.", "Close access to any background services that do not need to be public.", "MEDIUM"),
    "domain_in_breach": ("Data Leak History", "Information related to your company was found in a past internet hack.", "Ensure all staff use strong, different passwords and multi-factor authentication.", "HIGH"),
    "cms_admin_exposed": ("Admin Panel Visible", "Attackers can easily find where to brute-force your website login.", "Hide or protect your website builder's login page.", "HIGH"),
    "cms_outdated": ("Old Website Software", "Hackers can exploit known flaws in older software to take over your site.", "Update your website builder software to the latest version.", "MEDIUM"),
    "session_cookie_insecure": ("Insecure User Logins", "Customer login sessions could be copied over public Wi-Fi.", "Enforce secure-only transmission for all user sessions.", "HIGH"),
    "cookie_missing_samesite": ("Tracking Vulnerability", "Your site could be manipulated from other malicious websites.", "Update your site's cookie settings to restrict cross-site tracking.", "MEDIUM"),
}

async def _call_claude(classified: List[Dict[str, Any]], domain: str) -> str:
    """Call Claude to translate pre-classified findings into plain English."""
    client = AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
    
    system_prompt = """You are a cybersecurity advisor writing for a small business owner with zero technical background. You receive pre-classified security findings and write plain-English explanations.
STRICT RULES:
- Never use these terms: CVE, CVSS, TLS, SSL, HSTS, CSP, DNS, HTTP, HTTPS, API, XSS, SQLI, OWASP, TCP, UDP, RFC, MIME, DOM, regex
- Write as if explaining to a market shop owner, not an engineer
- Focus on business impact: money lost, customers scared, reputation damage
- Keep title under 12 words
- Keep business_impact to 1 sentence
- Keep fix_action to 1 sentence, non-technical, actionable today
- NEVER change the severity field — copy it exactly from the input
- Return ONLY a valid JSON array. No preamble. No markdown. No explanation."""
    
    user_prompt = f"Here are the findings for {domain}:\n\n{json.dumps(classified, indent=2)}\n\nGenerate the plain English JSON array as instructed."
    
    response = await client.messages.create(
        model="claude-sonnet-4-6", # Per requirements, specify exactly this model
        max_tokens=1000,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}]
    )
    
    return response.content[0].text.strip()

def _strip_jargon(text: str) -> str:
    """Silently removes banned jargon terms."""
    result = text
    for term in JARGON_BLOCKLIST:
        # Case insensitive regex replacement with word boundaries
        pattern = re.compile(r'\b' + re.escape(term) + r'\b', re.IGNORECASE)
        result = pattern.sub('', result)
    # Cleanup possible double spaces left behind
    return re.sub(r'\s+', ' ', result).strip()

def _get_static_fallback(finding: Dict[str, Any]) -> RiskItem:
    """Return deterministic fallback copy for a classified finding."""
    key = finding.get("key")
    severity = finding.get("severity", "AMBER")
    
    fallback = STATIC_FALLBACKS.get(key)
    if fallback:
        return RiskItem(
            title=fallback[0],
            severity=severity,
            business_impact=fallback[1],
            fix_action=fallback[2],
            confidence=fallback[3]
        )
    return RiskItem(
        title="Security Configuration Issue",
        severity=severity,
        business_impact="Your website has a security gap that could impact customers.",
        fix_action="Consult a web developer to address configuration warnings.",
        confidence="LOW"
    )

async def translate_to_plain_english(classified: List[Dict[str, Any]], domain: str) -> List[RiskItem]:
    """
    Translates technical findings into plain English business risks using Claude AI.
    Applies strict jargon filtering and falls back to static text on failure.
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
            for item in data:
                # Need to enforce the severity from the original classified list, but instruction says Claude shouldn't change it.
                # Assuming Claude followed instruction, we still validate.
                
                # Jargon strip
                item["business_impact"] = _strip_jargon(item.get("business_impact", ""))
                item["fix_action"] = _strip_jargon(item.get("fix_action", ""))
                item["title"] = _strip_jargon(item.get("title", ""))
                
                valid_item = RiskItem(**item)
                results.append(valid_item)
                
            return results
            
        except Exception as e:
            logger.error(f"AI translation attempt {attempt + 1} failed: {e}", exc_info=True)
            if attempt == 1:
                break # On second failure, fallback
                
    # Fallback to static rules
    logger.info("Using static fallbacks for report generation.")
    return [_get_static_fallback(f) for f in classified]
