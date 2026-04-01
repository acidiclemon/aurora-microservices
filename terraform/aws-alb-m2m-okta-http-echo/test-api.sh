#!/bin/bash

# ==============================================================================
# Testing the M2M Auth API Endpoint (Envoy + Okta)
# ==============================================================================
# This script contains the cURL commands required to test the Okta 
# Machine-to-Machine JWT authorization layer. You will need a valid M2M 
# Client ID and Client Secret generated from an Okta API Services Application.
# 
# Please replace the placeholder variables below with your actual Okta 
# credentials and your deployed API domain!
# ==============================================================================

OKTA_DOMAIN="https://your-domain.okta.com"
OKTA_AUTH_SERVER="default"
CLIENT_ID="YOUR_CLIENT_ID"
CLIENT_SECRET="YOUR_CLIENT_SECRET"
API_ENDPOINT="https://api.your-domain.com/"

echo "1. Requesting Bearer Token from Okta ($OKTA_DOMAIN)..."

# Replace this payload manually if you prefer not to use variables
TOKEN_RESPONSE=$(curl -s --request POST \
  --url "$OKTA_DOMAIN/oauth2/$OKTA_AUTH_SERVER/v1/token" \
  --header 'accept: application/json' \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data 'grant_type=client_credentials' \
  --data "client_id=$CLIENT_ID" \
  --data "client_secret=$CLIENT_SECRET" \
  --data 'scope=test')  # Add any custom scopes required by your Okta policy

# Extract the access token using a basic grep (requires jq in production)
ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

if [ -z "$ACCESS_TOKEN" ]; then
  echo "Failed to retrieve access token! Here is Okta's response:"
  echo "$TOKEN_RESPONSE"
  exit 1
fi

echo "Token successfully retrieved!"
echo ""

echo "2. Sending authenticated request to the Envoy Sidecar ($API_ENDPOINT)..."
curl -i "$API_ENDPOINT" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

echo ""
echo "Done!"
