#!/usr/bin/env bash
set -euo pipefail

CONTAINER="${1:?container required}"
PREV_IMAGE="${2:?previous image required}"
RUN_ARGS="${3:-}"

docker stop "$CONTAINER" >/dev/null 2>&1 || true
docker rm "$CONTAINER" >/dev/null 2>&1 || true
# shellcheck disable=SC2086
docker run -d --name "$CONTAINER" $RUN_ARGS "$PREV_IMAGE"
echo "[ok] rolled back $CONTAINER -> $PREV_IMAGE"
