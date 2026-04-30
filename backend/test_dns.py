import asyncio
import sys
from app.services.scanner.dns_check import run

async def main():
    try:
        res = await run("example.com")
        print("SUCCESS:", res)
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
