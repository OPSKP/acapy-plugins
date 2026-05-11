#!/bin/bash
set -e

echo "API_BASE_URL: $API_BASE_URL"
echo "Waiting for $API_BASE_URL..."

until curl --silent --fail $API_BASE_URL; do
  echo "Waiting for $API_BASE_URL..."
  sleep 2
done

echo "\n$API_BASE_URL is available"

TUNNEL_ENDPOINT=${TUNNEL_ENDPOINT:-http://ngrok:4040}


# Get the authserver tunnel public URL using jq
if [ -z "$AUTHSERVER_BASE_URL" ]; then
	AUTHSERVER_BASE_URL=$(curl --silent "${TUNNEL_ENDPOINT}/api/tunnels" | jq -r '.tunnels[] | select(.name == "authserver") | .public_url')
	export AUTHSERVER_BASE_URL
fi
echo "AUTHSERVER_BASE_URL: $AUTHSERVER_BASE_URL"

npm start