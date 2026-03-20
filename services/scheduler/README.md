# Scheduler service

Runs periodic health checks and writes audit events.

For packaged deployment examples, see [Delivery Guide](/Users/zhangza/code/agent/ops-agent/docs/DELIVERY.md).

Current command:

```bash
go run ./cmd/ops-scheduler --env test --env-file configs/environments.yaml --policy configs/policies.yaml --audit audit/scheduler.jsonl --notify-config configs/notifications.yaml --notify-trigger-after 2 --notify-recovery-after 2 --once
go run ./cmd/ops-scheduler --env prod --env-file configs/environments.yaml --policy configs/policies.yaml --audit audit/scheduler.jsonl --discover-interval 6h --discover-timeout 20s --discover-probe-timeout 1500ms
```

Each cycle checks local host basics plus the selected environment's configured hosts, host resource thresholds, optional host process watchlists, service endpoints, container restart/flap signals, systemd recent error summaries, and dependencies.
Host resource thresholds live under `hosts[].checks` and default to per-cpu load, memory, disk, and inode thresholds if omitted.
Service runtime/log thresholds live under `services[].checks`; containers default to restart-count/flap thresholds and systemd services default to a 30-minute `journalctl -p err` scan.
Container runtime checks now surface richer diagnostics including `oom_killed`, `exit_code`, `finished_at`, and recent restart timestamps.
Systemd log summaries now de-duplicate repeated error lines before they are attached to incidents or notifications.
If `--discover-interval` is set, the scheduler also runs the SSH-based discovery/apply flow on that lower cadence before health checks. That flow can auto-enroll Docker containers, matched systemd services, and safe standalone listeners into `configs/environments.yaml`.
If you prefer manual inventory control, leave `--discover-interval=0` and run `go run ./cmd/ops-agent discover ... --apply` on demand; the scheduler still reloads `configs/environments.yaml` on every cycle, so newly discovered services become part of the next health run without restarting the scheduler.
When an auto-applied service has no confirmed HTTP health endpoint, the scheduler falls back to TCP checks for discovered ports or `systemctl is-active` checks for systemd-only services.
If SSH to a host is already down, the incident layer suppresses that host's resource and process checks so notifications stay focused on the root cause.
If a host outage is already detected, services bound to that host can be marked as suppressed downstream symptoms instead of separate incidents.
If services define `slo`, the scheduler also evaluates history-backed availability burn rate and emits synthetic `slo_availability_*` results.
When notifier flags are set, warn/fail cycles are summarized into action suggestions and pushed to the configured destination.
`--notify-config` lets the scheduler route by env/source/severity and suppress planned work with silences or maintenance windows.
`--notify-trigger-after` and `--notify-recovery-after` let the scheduler wait for consecutive unhealthy or healthy cycles before changing incident state.
