# Scheduler service

Runs periodic health checks and writes audit events.

Current command:

```bash
go run ./cmd/ops-scheduler --env test --env-file configs/environments.yaml --policy configs/policies.yaml --audit audit/scheduler.jsonl --notify-webhook https://example.com/hook --once
```

Each cycle checks local host basics plus the selected environment's configured hosts, service endpoints, and dependencies.
When notifier flags are set, warn/fail cycles are summarized into action suggestions and pushed to the configured destination.
