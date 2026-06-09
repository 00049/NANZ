import asyncio
from app.db.session import engine
from sqlalchemy import text

async def update():
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE users DROP COLUMN IF EXISTS plan;"))
        print("Column dropped successfully!")

asyncio.run(update())
