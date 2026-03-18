#!/usr/bin/env bash
set -euo pipefail

CHECKS="${1:-}" # format: tcp://127.0.0.1:6379,http://127.0.0.1:8080/health
if [[ -z "$CHECKS" ]]; then
  echo "[info] no dependency checks provided"
  exit 0
fi

IFS=',' read -ra ITEMS <<< "$CHECKS"
for item in "${ITEMS[@]}"; do
  item="$(echo "$item" | xargs)"
  [[ -z "$item" ]] && continue

  if [[ "$item" == tcp://* ]]; then
    target="${item#tcp://}"
    host="${target%:*}"
    port="${target##*:}"
    if timeout 3 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
      echo "[ok] tcp $host:$port"
    else
      echo "[fail] tcp $host:$port"
      exit 1
    fi
  elif [[ "$item" == http://* || "$item" == https://* ]]; then
    if curl -fsS --max-time 5 "$item" >/dev/null; then
      echo "[ok] http $item"
    else
      echo "[fail] http $item"
      exit 1
    fi
  else
    echo "[warn] unsupported check: $item"
  fi
done
