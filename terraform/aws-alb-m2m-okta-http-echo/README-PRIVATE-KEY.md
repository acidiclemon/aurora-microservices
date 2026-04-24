# Okta Private Key JWT Authentication Guide for Ubuntu 24

Generating a perfectly formatted, signed JWT entirely inside a bash terminal using `curl` and `openssl` is notoriously difficult and fragile. The industry standard is to use a lightweight scripting language like Python.

Here are the exact terminal steps to perform this flow on your Ubuntu 24 machine:

## Step 1: Install Python JWT Library
You will need the Python JWT and Cryptography libraries to securely sign the token.
```bash
sudo apt update
sudo apt install -y python3-pip python3-venv
python3 -m venv venv
source venv/bin/activate
pip install PyJWT cryptography
```

## Step 2: Generate your RSA Key Pair
Run this `openssl` command in your terminal. It will generate two files: `private.pem` (your secret) and `public.pem` (what you give to Okta).
```bash
# 1. Generate the private key
openssl genrsa -out private.pem 2048

# 2. Extract the public key
openssl rsa -in private.pem -pubout -out public.pem
```

## Step 3: Configure Okta
1. Log into your Okta Admin Console.
2. Go to your API Services Application.
3. In the **General** tab, under "Client Credentials", change the authentication method to **Public Key / Private Key**.
4. Click **Add Key** and upload the `public.pem` file you just generated.
5. Save your changes.

## Step 4: Run the Script
1. Open the `okta-private-key-auth.py` script provided in this directory.
2. Replace `YOUR_CLIENT_ID` and the `OKTA_TOKEN_URL` with your actual Okta details.
3. Run the script!

```bash
python3 okta-private-key-auth.py
```

The script will automatically read your `private.pem` file, generate a perfectly signed JWT, exchange it with Okta, and output the final `curl` command you need to hit your Envoy API!
