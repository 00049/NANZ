import json
import ssl
import urllib.request

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

data = json.dumps(
    {
        "name": "Test User",
        "email": "test@example.com",
        "password": "password123",
        "company": "Test Company",
    }
).encode("utf-8")

req = urllib.request.Request(
    "http://localhost:8000/api/auth/register",
    data=data,
    headers={"Content-Type": "application/json"},
)

try:
    response = urllib.request.urlopen(req, context=ctx)
    print(response.read().decode("utf-8"))
except urllib.error.URLError as e:
    if hasattr(e, "read"):
        print(e.read().decode("utf-8"))
    else:
        print(e)
