import asyncio
import httpx
import time

API_URL = "http://127.0.0.1:8000/api/v1/scans"
TEST_URLS = [
    "https://example.com",
    "https://google.com",
    "https://github.com",
    "https://example.com", # Duplicate rapid request test
    "https://example.com", # Duplicate rapid request test
    "https://example.com", # Duplicate rapid request test
]

async def fire_request(client, url):
    payload = {"url": url}
    start = time.time()
    try:
        response = await client.post(API_URL, json=payload, timeout=15.0)
        end = time.time()
        res_json = response.json()
        duration = int((end - start) * 1000)
        print(f"[{response.status_code}] {url} -> {res_json.get('status')} in {duration}ms")
    except Exception as e:
        end = time.time()
        duration = int((end - start) * 1000)
        print(f"[FAIL] {url} -> {str(e)} in {duration}ms")

async def stress_test():
    print(f"Starting stress test making {len(TEST_URLS)} concurrent requests...")
    async with httpx.AsyncClient() as client:
        tasks = [fire_request(client, url) for url in TEST_URLS]
        await asyncio.gather(*tasks)
    print("Stress test dispatch completed.")

if __name__ == "__main__":
    asyncio.run(stress_test())
