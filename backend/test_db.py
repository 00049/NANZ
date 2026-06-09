import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

async def main():
    url = "postgresql+asyncpg://postgres.lkcvhjmwkjfuvfmzpqru:%267Ja54GSK%2Fv%2C%2B%24E@aws-1-ap-south-1.pooler.supabase.com:6543/postgres"
    
    print(f"Testing SQLAlchemy connection with: {url}")
    engine = create_async_engine(url)
    
    try:
        async with engine.begin() as conn:
            result = await conn.execute(text("SELECT * FROM users LIMIT 1"))
            print(f"SUCCESS! Table exists. Rows returned: {len(result.fetchall())}")
    except Exception as e:
        print(f"FAILED: {type(e).__name__} - {e}")
    finally:
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(main())
