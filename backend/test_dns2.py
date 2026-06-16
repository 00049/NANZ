import asyncio
from app.services.scanner.dns_check import run

async def main():
    res = await run("www.bennett.edu.in")
    print(res)

if __name__ == "__main__":
    asyncio.run(main())
