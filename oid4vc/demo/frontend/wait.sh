#!/bin/sh
# wait.sh: Wait for the issuer/ any service to be available before starting the frontend application.

set -e

host="$1"
port="$2"
shift 2

until nc -z "$host" "$port"; do
  echo "Waiting for $host:$port to be available..."
  sleep 2
done

exec "$@"
