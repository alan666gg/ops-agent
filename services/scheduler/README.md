# Scheduler service

Runs periodic health checks and writes audit events.

Current command:

```bash
go run ./cmd/ops-scheduler --env test --env-file configs/environments.yaml --audit audit/scheduler.jsonl --once
```

Each cycle checks local host basics plus the selected environment's configured hosts, service endpoints, and dependencies.
