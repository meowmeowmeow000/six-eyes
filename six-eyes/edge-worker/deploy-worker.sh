#!/bin/bash
set -euo pipefail

WORKER_NAME="${1:-six-eyes-edge}"
cd "$(dirname "$0")"

cat << TOML > wrangler.toml
name = "$WORKER_NAME"
main = "worker.js"
compatibility_date = "2026-11-09"
TOML

echo "[+] Deploying SMUX v1 Worker ($WORKER_NAME) via Cloudflare Wrangler..."
if ! npx wrangler whoami >/dev/null 2>&1; then
  echo "[-] Wrangler is not authenticated. Run 'npx wrangler login' first or set CLOUDFLARE_API_TOKEN." >&2
  exit 1
fi
npx wrangler deploy
