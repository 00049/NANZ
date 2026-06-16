from dataclasses import dataclass, field

import httpx

from app.config import settings


@dataclass
class BreachResult:
    checked: bool = False
    breached: bool = False
    breach_count: int = 0
    breach_names: list[str] = field(default_factory=list)
    latest_breach_date: str | None = None
    error: str | None = None


async def run(domain: str) -> BreachResult:
    """
    Checks the Have I Been Pwned API for domain breaches.
    """
    if not settings.HIBP_API_KEY:
        return BreachResult(checked=False)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.get(
                f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                headers={"hibp-api-key": settings.HIBP_API_KEY},
            )

            if res.status_code == 404:
                return BreachResult(checked=True, breached=False)

            if res.status_code == 200:
                data = res.json()
                # HIBP breacheddomain endpoint currently returns a dictionary of breaches or just domain info depending on tier.
                # Assuming generic response structure per instructions.
                breaches = data if isinstance(data, dict) else {}

                names = list(breaches.keys())

                return BreachResult(
                    checked=True,
                    breached=len(names) > 0,
                    breach_count=len(names),
                    breach_names=names[:5],  # Limit size
                    latest_breach_date="Unknown",  # Cannot always pinpoint without full breach data iteration
                )
            else:
                return BreachResult(
                    checked=True, error=f"HIBP API error {res.status_code}"
                )

    except Exception as e:
        return BreachResult(checked=True, error=str(e))
