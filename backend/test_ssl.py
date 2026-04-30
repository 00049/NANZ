import asyncio
from app.services.scanner.ssl_check import run

async def main():
    try:
        res = await run("stripe.com")
        print("SUCCESS:", res)
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
