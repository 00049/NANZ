import asyncio
import os

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("No DATABASE_URL")
    exit(1)


async def check():
    engine = create_async_engine(DATABASE_URL)
    async with engine.connect() as conn:
        from sqlalchemy import text

        res = await conn.execute(
            text("SELECT email FROM users WHERE email='saravpreet30@gmail.com'")
        )
        row = res.fetchone()
        if row:
            print("Found:", row[0])
        else:
            print("Not found")


asyncio.run(check())
