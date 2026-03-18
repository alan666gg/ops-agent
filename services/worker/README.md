# Worker service

Executes runbooks with policy guardrails and writes audit events.

Current command:

```bash
go run ./cmd/ops-worker --action check_host_health --policy configs/policies.yaml --audit audit/worker.jsonl
```
