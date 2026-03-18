#!/usr/bin/env bash
set -euo pipefail

URL="${1:-http://127.0.0.1:8080/}"
if curl -fsS --max-time 5 "$URL" >/dev/null; then
  echo "[ok] service healthy: $URL"
else
  echo "[fail] service unhealthy: $URL"
  exit 1
fi
