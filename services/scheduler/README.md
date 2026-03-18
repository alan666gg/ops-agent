# Scheduler service

Runs periodic health checks and writes audit events.

Current command:

```bash
go run ./cmd/ops-scheduler --env test --env-file configs/environments.yaml --policy configs/policies.yaml --audit audit/scheduler.jsonl --notify-config configs/notifications.yaml --notify-trigger-after 2 --notify-recovery-after 2 --once
```

Each cycle checks local host basics plus the selected environment's configured hosts, service endpoints, and dependencies.
If a host outage is already detected, services bound to that host can be marked as suppressed downstream symptoms instead of separate incidents.
When notifier flags are set, warn/fail cycles are summarized into action suggestions and pushed to the configured destination.
`--notify-config` lets the scheduler route by env/source/severity and suppress planned work with silences or maintenance windows.
`--notify-trigger-after` and `--notify-recovery-after` let the scheduler wait for consecutive unhealthy or healthy cycles before changing incident state.
