import urllib.request, urllib.parse, json, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

data_reg = json.dumps({
    'name': 'Test User',
    'email': 'saravpreet30@gmail.com',
    'password': 'password123',
    'company': 'NANZ User'
}).encode('utf-8')
req_reg = urllib.request.Request('http://localhost:10001/api/auth/register', data=data_reg, headers={'Content-Type': 'application/json'})
try:
    res = urllib.request.urlopen(req_reg, context=ctx)
    print(res.getcode())
    print(res.read().decode('utf-8'))
except urllib.error.HTTPError as e:
    print('HTTPError', e.code)
    print(e.read().decode('utf-8'))
