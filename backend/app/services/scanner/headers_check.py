import httpx
from dataclasses import dataclass, field
from typing import Optional

REQUIRED_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
]

@dataclass
class HeadersResult:
    present: dict[str, str] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    score: int = 0
    server_header: Optional[str] = None
    x_powered_by: Optional[str] = None
    error: Optional[str] = None

async def run(url: str) -> HeadersResult:
    """
    Fetches the URL and analyzes the HTTP security headers returned by the server.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(url, headers={
                "User-Agent": "ShieldCheck-Scanner/1.0 (+https://shieldcheck.in/bot)"
            })
            
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            
            present = {}
            missing = []
            
            for req_h in REQUIRED_HEADERS:
                if req_h in headers_lower:
                    present[req_h] = headers_lower[req_h]
                else:
                    missing.append(req_h)
                    
            score = int((len(present) / len(REQUIRED_HEADERS)) * 100)
            
            server_hdr = headers_lower.get("server")
            x_powered = headers_lower.get("x-powered-by")
            
            return HeadersResult(
                present=present,
                missing=missing,
                score=score,
                server_header=server_hdr,
                x_powered_by=x_powered
            )
            
    except Exception as e:
        return HeadersResult(error=str(e))
