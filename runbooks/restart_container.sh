#!/usr/bin/env bash
set -euo pipefail

CONTAINER="${1:?container name required}"
docker restart "$CONTAINER"
echo "[ok] restarted $CONTAINER"
