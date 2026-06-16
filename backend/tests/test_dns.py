import asyncio
import sys

from app.services.scanner.dns_check import run


async def test_dns():
    try:
        res = await run("example.com")
        print("SUCCESS:", res)
    except Exception:
        import traceback

        traceback.print_exc()
