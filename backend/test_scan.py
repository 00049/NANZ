import asyncio
from app.services.scanner.orchestrator import run_full_scan
from redis.asyncio import Redis

async def main():
    redis_client = Redis.from_url("redis://localhost:6379")
    # Provide a fake uuid
    await run_full_scan("6948f91a-7a1a-46b4-ab66-c733849b97cd", "https://www.bennett.edu.in/", redis_client)

if __name__ == "__main__":
    asyncio.run(main())
