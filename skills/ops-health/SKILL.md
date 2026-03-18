---
name: ops-health
description: Health checks for hosts, services, and dependencies. Use when checking uptime, CPU/memory/disk, endpoint health, or dependency connectivity before deployment.
---

Run these runbooks:
- `runbooks/check_host_health.sh`
- `runbooks/check_service_health.sh <url>`
- `runbooks/check_dependencies.sh "tcp://host:port,http://..."`
