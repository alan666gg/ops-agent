# ops-agent

Internal Ops Agent scaffold with policy-gated runbooks, approvals, and audit trails.

## Structure

- `skills/` domain skills for health/incident/deploy
- `runbooks/` executable guarded operations
- `configs/` environment and policy configs
- `services/` api/scheduler/worker placeholders
- `docs/` architecture and roadmap

## Quick start

1. Fill `configs/environments.yaml`
2. Review `configs/policies.yaml`
3. Run health checks via runbooks

## Go engine (initial)

```bash
go run ./cmd/ops-agent health --url http://127.0.0.1:8080/ --dep redis:127.0.0.1:6379
```

Policy evaluation + audit:

```bash
go run ./cmd/ops-agent policy --action restart_container --env prod --policy configs/policies.yaml --audit audit/events.jsonl
```

Config validation:

```bash
go run ./cmd/ops-agent validate --env-file configs/environments.yaml --policy configs/policies.yaml --notify-config configs/notifications.yaml
```

Scheduler (periodic health checks):

```bash
go run ./cmd/ops-scheduler --env test --env-file configs/environments.yaml --audit audit/scheduler.jsonl --once
```

The scheduler/API health pass now includes:

- local agent host basics
- SSH reachability for each host declared under `environments.<env>.hosts`
- service HTTP checks from `services[].healthcheck_url`
- HTTP/TCP dependency checks from `dependencies[]`

Worker (policy-gated runbook execution):

```bash
# low-risk action (allowed)
go run ./cmd/ops-worker --action check_host_health --env test --policy configs/policies.yaml --audit audit/worker.jsonl

# action requiring approval
go run ./cmd/ops-worker --action restart_container --env prod --args cicdtest-app --policy configs/policies.yaml --audit audit/worker.jsonl --approved

# run the action on a configured ssh host in the environment
go run ./cmd/ops-worker --action restart_container --env prod --env-file configs/environments.yaml --target-host app-1 --args cicdtest-app --policy configs/policies.yaml --audit audit/worker.jsonl --approved
```

API (minimal control plane):

```bash
export OPS_API_TOKEN=change-me
go run ./cmd/ops-api --addr :8090 --env-file configs/environments.yaml --policy configs/policies.yaml --audit audit/api.jsonl --pending-driver sqlite --pending-file audit/pending-actions.db --pending-ttl 24h --rate-limit-window 1m --rate-limit-max 120 --notify-config configs/notifications.yaml --notify-trigger-after 2 --notify-recovery-after 2
```

Quick test:

```bash
curl -s http://127.0.0.1:8090/ready
curl -s "http://127.0.0.1:8090/health/run?env=test" -H "Authorization: Bearer $OPS_API_TOKEN"

# notify on demand for manual health runs
curl -s "http://127.0.0.1:8090/health/run?env=prod&notify=1" -H "Authorization: Bearer $OPS_API_TOKEN"

# test environment action can auto-execute
curl -s -X POST http://127.0.0.1:8090/actions/run \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $OPS_API_TOKEN" \
  -d '{"action":"check_host_health","env":"test","actor":"local-dev"}'

# execute on a remote host declared in the environment config
curl -s -X POST http://127.0.0.1:8090/actions/run \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $OPS_API_TOKEN" \
  -d '{"action":"restart_container","env":"prod","target_host":"app-1","args":["cicdtest-app"],"approved":true,"actor":"local-dev"}'

# request approval-required action
REQ_ID=$(curl -s -X POST http://127.0.0.1:8090/actions/request \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $OPS_API_TOKEN" \
  -d '{"action":"restart_container","env":"prod","args":["cicdtest-app"],"actor":"local-dev"}' | jq -r .request_id)

# list pending and approve
curl -s "http://127.0.0.1:8090/actions/pending" -H "Authorization: Bearer $OPS_API_TOKEN"
curl -s "http://127.0.0.1:8090/actions/list?status=executed&limit=20" -H "Authorization: Bearer $OPS_API_TOKEN"
# cursor pagination: use next_cursor from previous response
curl -s "http://127.0.0.1:8090/actions/list?status=pending&limit=20&cursor=<next_cursor>" -H "Authorization: Bearer $OPS_API_TOKEN"
curl -s -X POST http://127.0.0.1:8090/actions/approve \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $OPS_API_TOKEN" \
  -d "{\"request_id\":\"$REQ_ID\",\"approver\":\"ops-admin\"}"

curl -s "http://127.0.0.1:8090/audit/tail?file=api.jsonl&limit=20" -H "Authorization: Bearer $OPS_API_TOKEN"
curl -s "http://127.0.0.1:8090/incidents/summary?minutes=60" -H "Authorization: Bearer $OPS_API_TOKEN"
curl -s "http://127.0.0.1:8090/metrics"
```

## Guardrails

- Supported actions come from a single action registry in `internal/actions`.
- Production guardrails apply when `env=prod` or `env=production`.
- `policies.production.require_human_approval=true` upgrades otherwise-safe actions to approval-required in production.
- `policies.production.max_auto_actions_per_hour` limits unattended production actions per hour; excess requests are converted to approval-required.
- `policies.forbidden_commands` now blocks actions whose runbook content contains a forbidden command token.
- `GET /audit/tail` only reads `.jsonl` files inside the configured audit directory.
- `target_host` lets `ops-worker` and `ops-api` run a runbook over SSH on a host declared under the chosen environment.
- Environment health checks run concurrently while keeping a stable output order.

## Notifications

- `ops-scheduler` can send warn/fail health reports automatically with `--notify-webhook`, `--notify-slack-webhook`, or `--notify-telegram-bot-token` + `--notify-telegram-chat-id`.
- `ops-api` supports the same notifier flags, but `/health/run` only sends when `notify=1` is present.
- `--notify-config` loads routing rules, named receivers, silences, and maintenance windows from `configs/notifications.yaml`.
- Notification routes currently match on `env`, `source`, and `severity`, and support a default receiver fallback.
- Active silences and maintenance windows suppress notifications without stopping health checks; if an issue survives the mute window, the controller will deliver it after the window ends.
- `--notify-trigger-after` and `--notify-recovery-after` let you suppress flapping by requiring consecutive unhealthy or healthy cycles before opening or closing an incident.
- Health responses now include `summary` and `suggestions` so callers can build their own incident workflow.
