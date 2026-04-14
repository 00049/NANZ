import httpx
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class CookieResult:
    total_cookies: int = 0
    insecure_cookies: list[dict] = field(default_factory=list)
    session_cookies_insecure: bool = False
    all_have_samesite: bool = True
    error: Optional[str] = None

SESSION_KEYWORDS = ["session", "sess", "auth", "token", "login", "user", "uid", "id"]

async def run(url: str) -> CookieResult:
    """
    Analyzes Set-Cookie headers for security flags.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            res = await client.get(url, headers={
                "User-Agent": "ShieldCheck-Scanner/1.0 (+https://shieldcheck.in/bot)"
            })
            
            raw_cookies = res.headers.get_list("set-cookie")
            if not raw_cookies:
                return CookieResult()
                
            insecure_cookies = []
            session_insecure = False
            all_samesite_present = True
            
            for cookie_str in raw_cookies:
                parts = cookie_str.split(";")
                if not parts:
                    continue
                    
                name_val = parts[0].strip()
                name = name_val.split("=")[0].strip() if "=" in name_val else name_val
                
                flags_lower = [p.strip().lower() for p in parts[1:]]
                
                missing_flags = []
                is_httponly = "httponly" in flags_lower
                is_secure = "secure" in flags_lower
                has_samesite = any(f.startswith("samesite=") for f in flags_lower)
                
                if not is_httponly: missing_flags.append("HttpOnly")
                if not is_secure: missing_flags.append("Secure")
                if not has_samesite: 
                    missing_flags.append("SameSite")
                    all_samesite_present = False
                    
                if missing_flags:
                    insecure_cookies.append({
                        "name": name,
                        "missing_flags": missing_flags
                    })
                    
                    is_session = any(k in name.lower() for k in SESSION_KEYWORDS)
                    if is_session and (not is_httponly or not is_secure):
                        session_insecure = True
                        
            return CookieResult(
                total_cookies=len(raw_cookies),
                insecure_cookies=insecure_cookies,
                session_cookies_insecure=session_insecure,
                all_have_samesite=all_samesite_present
            )
            
    except Exception as e:
        return CookieResult(error=str(e))
