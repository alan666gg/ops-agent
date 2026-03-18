# Worker service

Executes runbooks with policy guardrails and writes audit events.

Current command:

```bash
go run ./cmd/ops-worker --action check_host_health --env test --policy configs/policies.yaml --audit audit/worker.jsonl
```

Notes:

- `--env prod` or `--env production` enables production policy guardrails.
- Production-safe actions can still be upgraded to approval-required based on `configs/policies.yaml`.
- `--target-host <name>` runs the runbook on the named host from `--env-file` via SSH.
