import asyncio
import os
import httpx
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("LEAKIX_API_KEY")

async def test_leakix():
    if not api_key:
        print("❌ LEAKIX_API_KEY is missing from .env")
        return
    
    print(f"Testing LeakIX API with key starting with: {api_key[:4]}...")
    
    headers = {"Accept": "application/json"}
    headers["api-key"] = api_key
    
    try:
        # Test endpoint by querying a common domain to see if auth works
        async with httpx.AsyncClient() as client:
            response = await client.get("https://leakix.net/domain/example.com", headers=headers, timeout=10.0)
            
            if response.status_code == 200:
                print("✅ LeakIX API is working! Received 200 OK.")
            elif response.status_code == 401:
                print("❌ Unauthorized: The API key is invalid or expired (401).")
            elif response.status_code == 429:
                print("⚠️ Rate limited (429). The key works but is rate limited.")
            else:
                print(f"⚠️ Unexpected status code: {response.status_code}")
                
    except Exception as e:
        print(f"❌ Error connecting to LeakIX: {e}")

asyncio.run(test_leakix())
