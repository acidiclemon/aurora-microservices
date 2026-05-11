#!/usr/bin/env python3
import json
import time
import uuid
import urllib.request
import urllib.parse
import sys

try:
    import jwt
except ImportError:
    print("Error: PyJWT is not installed. Run: pip install PyJWT cryptography")
    sys.exit(1)

# ==========================================================
# Configuration variables
# ==========================================================
CLIENT_ID = "YOUR_CLIENT_ID"
OKTA_TOKEN_URL = "https://your-domain.okta.com/oauth2/default/v1/token"
PRIVATE_KEY_FILE = "private.pem"
SCOPE = "test"

print(f"Loading private key from {PRIVATE_KEY_FILE}...")
try:
    with open(PRIVATE_KEY_FILE, 'rb') as f:
        private_key = f.read()
except FileNotFoundError:
    print(f"Error: Could not find '{PRIVATE_KEY_FILE}'. Did you generate it?")
    sys.exit(1)

print("Generating Signed Client Assertion JWT...")
# The payload required by Okta for private_key_jwt authentication
payload = {
    "iss": CLIENT_ID,
    "sub": CLIENT_ID,
    "aud": OKTA_TOKEN_URL,
    "exp": int(time.time()) + 300, # Expires in 5 minutes
    "jti": str(uuid.uuid4())
}

# Sign the assertion using the RS256 algorithm and the private key
client_assertion = jwt.encode(payload, private_key, algorithm="RS256")

print("Sending request to Okta...")
data = urllib.parse.urlencode({
    "grant_type": "client_credentials",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": client_assertion,
    "scope": SCOPE
}).encode("utf-8")

req = urllib.request.Request(OKTA_TOKEN_URL, data=data)
req.add_header('Accept', 'application/json')
req.add_header('Content-Type', 'application/x-www-form-urlencoded')

try:
    with urllib.request.urlopen(req) as response:
        response_data = json.loads(response.read().decode())
        print("\n✅ SUCCESS! Here is your Access Token:\n")
        print(response_data.get("access_token"))
        print("\nUse this token in your curl command to hit the API:")
        print(f'curl -i https://api.your-domain.com/ -H "Authorization: Bearer {response_data.get("access_token")}"')
except urllib.error.HTTPError as e:
    print("\n❌ Okta rejected the request:")
    print(f"Status Code: {e.code}")
    print(e.read().decode())
