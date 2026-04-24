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
    
    # Convert to JSON Web Key (JWK)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(public_key)
    
    # Okta specifically requires a JWK "Set" (JWKS) with a keys array
    jwks = {
        "keys": [jwk]
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
