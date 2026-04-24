#!/usr/bin/env python3
import json
import sys

try:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: PyJWT and cryptography are required. Run: pip install PyJWT cryptography")
    sys.exit(1)

PUBLIC_KEY_FILE = "public.pem"

try:
    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key_bytes = f.read()
    
    # Load the PEM public key
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
    
    # PyJWT's to_jwk returns a JSON string, so we must parse it into a dict
    jwk_json_str = jwt.algorithms.RSAAlgorithm.to_jwk(public_key)
    jwk_dict = json.loads(jwk_json_str)
    
    # Okta strictly requires a Key ID (kid) to uniquely identify the key
    jwk_dict["kid"] = "my-api-key-1"
    
    # Okta specifically requires a JWK "Set" (JWKS) with a keys array containing the object
    jwks = {
        "keys": [jwk_dict]
    }
    
    print("\n✅ Successfully converted PEM to JWKS format!")
    print("Copy the entire JSON block below and paste it into Okta:\n")
    print("--------------------------------------------------")
    print(json.dumps(jwks, indent=2))
    print("--------------------------------------------------\n")
    
except FileNotFoundError:
    print(f"Error: Could not find '{PUBLIC_KEY_FILE}'")
except Exception as e:
    print(f"An error occurred: {e}")
