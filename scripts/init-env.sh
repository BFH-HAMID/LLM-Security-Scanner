#!/bin/sh
# Create .env from .env.example with freshly generated secrets. Never overwrites an existing .env.
set -eu
cd "$(dirname "$0")/.."

if [ -e .env ]; then
  echo ".env already exists; leaving it alone."
  exit 0
fi

secret() { head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

api_key="llmscan_$(secret)"
pg_pass="$(secret)"

umask 077
sed -e "s/^LLMSCAN_API_KEY=.*/LLMSCAN_API_KEY=${api_key}/" \
    -e "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${pg_pass}/" \
    .env.example > .env

echo "Wrote .env with a new API key and database password (mode 600)."
echo "Next: docker compose up -d --build   (dashboard: http://localhost:3000)"
