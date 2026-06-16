import asyncio

from app.services.scanner.ssl_check import run


async def test_ssl():
    try:
        res = await run("stripe.com")
        print("SUCCESS:", res)
    except Exception:
        import traceback

        traceback.print_exc()
