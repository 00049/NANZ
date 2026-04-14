import re
import httpx
import urllib.parse
from dataclasses import dataclass
from typing import Optional

@dataclass
class CMSResult:
    cms_type: Optional[str] = None
    detected_version: Optional[str] = None
    latest_known_version: Optional[str] = None
    outdated_version: bool = False
    admin_exposed: bool = False
    error: Optional[str] = None

async def run(url: str) -> CMSResult:
    """
    Detects CMS type, version, and exposed admin panels.
    """
    result = CMSResult(latest_known_version="6.5.3") # Hardcoded for WordPress initially
    
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            res = await client.get(url, headers={
                "User-Agent": "ShieldCheck-Scanner/1.0 (+https://shieldcheck.in/bot)"
            })
            html = res.text
            headers = {k.lower(): v for k, v in res.headers.items()}
            
            # 1. WordPress Detection
            wp_match = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', html, re.IGNORECASE)
            if wp_match:
                result.cms_type = "wordpress"
                result.detected_version = wp_match.group(1)
                
            elif "wp-content" in html or "wp-includes" in html:
                result.cms_type = "wordpress"
                
            # 2. Shopify Detection
            elif "Shopify.theme" in html or "cdn.shopify.com" in html:
                result.cms_type = "shopify"
                result.detected_version = "SaaS"

            # 3. Generic header detection
            if not result.cms_type:
                server = headers.get("server", "").lower()
                x_powered_by = headers.get("x-powered-by", "").lower()
                if "wordpress" in x_powered_by:
                    result.cms_type = "wordpress"

            # Check admin panel (WordPress only for MVP)
            if result.cms_type == "wordpress":
                base_url = f"{res.url.scheme}://{res.url.host}"
                admin_res = await client.get(f"{base_url}/wp-login.php")
                if admin_res.status_code == 200:
                    result.admin_exposed = True
                    
                # Update version outdated check
                if result.detected_version and result.detected_version != result.latest_known_version:
                    result.outdated_version = True
                    
            if not result.cms_type:
                result.cms_type = "unknown"
                
            return result
            
    except Exception as e:
        result.error = str(e)
        return result
