#!/usr/bin/env bash
set -euo pipefail

echo "[host] $(hostname)"
echo "[time] $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[cpu]" && uptime
echo "[mem]" && free -h
echo "[disk]" && df -h
