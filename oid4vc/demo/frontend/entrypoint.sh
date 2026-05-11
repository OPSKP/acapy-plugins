#!/bin/bash
set -e

TUNNEL_ENDPOINT=${TUNNEL_ENDPOINT:-http://ngrok:4040}


# Get the authserver tunnel public URL using jq
if [ -z "$AUTHSERVER_BASE_URL" ]; then
	AUTHSERVER_BASE_URL=$(curl --silent "${TUNNEL_ENDPOINT}/api/tunnels" | jq -r '.tunnels[] | select(.name == "authserver") | .public_url')
	export AUTHSERVER_BASE_URL
fi
echo "AUTHSERVER_BASE_URL: $AUTHSERVER_BASE_URL"

exec "$@"
