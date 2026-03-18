# Scheduler service

Runs periodic health checks and writes audit events.

Current command:

```bash
go run ./cmd/ops-scheduler --env test --env-file configs/environments.yaml --audit audit/scheduler.jsonl --once
```
