import asyncio

from sqlalchemy import text

from app.db.session import engine


async def update():
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE users DROP COLUMN IF EXISTS plan;"))
        print("Column dropped successfully!")


asyncio.run(update())
