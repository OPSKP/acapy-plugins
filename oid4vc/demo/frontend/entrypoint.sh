#!/bin/bash
set -e

TUNNEL_ENDPOINT=${TUNNEL_ENDPOINT:-http://ngrok:4040}

# Get the keycloak tunnel public URL using jq
KEYCLOAK_NGROK_URL=$(curl --silent "${TUNNEL_ENDPOINT}/api/tunnels" | jq -r '.tunnels[] | select(.name == "keycloak") | .public_url')
export KEYCLOAK_NGROK_URL
echo "KEYCLOAK_NGROK_URL: $KEYCLOAK_NGROK_URL"

exec "$@"
