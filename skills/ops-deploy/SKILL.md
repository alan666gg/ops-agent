---
name: ops-deploy
description: Controlled deploy and rollback operations for containerized services. Use for pre-deploy checks, release execution, and rollback actions.
---

Safe deploy checklist:
1. run dependency checks
2. deploy release
3. run service health check
4. rollback if health check fails
