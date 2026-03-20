# ops-agent

Internal Ops Agent scaffold with policy-gated runbooks, approvals, and audit trails.

## Structure

- `skills/` domain skills for health/incident/deploy
- `runbooks/` executable guarded operations
- `configs/` environment and policy configs
- `services/` api/scheduler/telegram usage notes
- `docs/` architecture and roadmap

## Quick start

1. Fill `configs/environments.yaml`
2. Review `configs/policies.yaml`
3. Link services to hosts in `configs/environments.yaml` when you want root-cause suppression to treat host outages as the primary incident
4. Run health checks via runbooks

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
go run ./cmd/ops-agent validate --env-file configs/environments.yaml --policy configs/policies.yaml --notify-config configs/notifications.yaml --chatops-config configs/chatops.yaml
```

Prometheus query:

```bash
go run ./cmd/ops-agent promql --env-file configs/environments.yaml --env test --query 'up'
go run ./cmd/ops-agent promql --env-file configs/environments.yaml --env prod --query 'avg(rate(http_requests_total[5m]))' --minutes 30 --step 60s --format json
```

Host discovery (Docker + systemd + listening ports over SSH):

```bash
go run ./cmd/ops-agent discover --env-file configs/environments.yaml --env prod --host app-1 --format yaml
# optional file output
go run ./cmd/ops-agent discover --env-file configs/environments.yaml --env prod --host app-1 --format json --out audit/discovery-app-1.json
# one-step onboarding: discover container/systemd/listener services, probe health URLs, and write back into environments.yaml
go run ./cmd/ops-agent discover --env-file configs/environments.yaml --env prod --host app-1 --apply
```

Scheduler (periodic health checks):

```bash
go run ./cmd/ops-scheduler --env test --env-file configs/environments.yaml --audit audit/scheduler.jsonl --once
# optional low-frequency inventory refresh alongside high-frequency health checks
go run ./cmd/ops-scheduler --env prod --env-file configs/environments.yaml --audit audit/scheduler.jsonl --discover-interval 6h --discover-timeout 20s
# recommended for larger installs: move audit history to sqlite
go run ./cmd/ops-scheduler --env prod --env-file configs/environments.yaml --audit audit/scheduler.db --audit-driver sqlite --discover-interval 6h
```

The scheduler/API health pass now includes:

- local agent host basics
- SSH reachability for each host declared under `environments.<env>.hosts`
- remote host resource checks over SSH for load-per-cpu, memory, disk, and inode usage
- optional remote process watchlists from `hosts[].checks.required_processes`
- service HTTP checks from `services[].healthcheck_url`
- container runtime checks for restart count and recent restart flapping
- systemd recent error-log summaries from `journalctl`
- HTTP/TCP dependency checks from `dependencies[]`
- Redis protocol checks from `redis://host:port/db`
- MySQL handshake checks from `mysql://host:port/db`
- optional history-backed SLO burn-rate checks from `services[].slo`

Host-level SSH resource checks are configured under `hosts[].checks` in [configs/environments.yaml](/Users/zhangza/code/agent/ops-agent/configs/environments.yaml). If you omit them, the control plane uses sensible defaults:

- `load_warn_per_cpu=1.5`, `load_fail_per_cpu=2.5`
- `memory_warn_percent=85`, `memory_fail_percent=95`
- `disk_warn_percent=80`, `disk_fail_percent=90`
- `inode_warn_percent=80`, `inode_fail_percent=90`
- `filesystem_path=/`

Service runtime/log checks are configured under `services[].checks`. Defaults are type-aware:

- container services: `restart_warn_count=2`, `restart_fail_count=5`, `restart_flap_window=15m`
- systemd services: `journal_window=30m`, `journal_lines=3`

Container runtime checks now surface richer failure context such as `oom_killed=true`, `exit_code`, `finished_at`, and recent restart timing.
Systemd log checks now de-duplicate repeated journal lines into compact summaries so notifications and chat replies stay readable.

Service discovery is now a low-frequency companion step to the scheduler. `ops-agent discover` can SSH into a declared host, list Docker containers, running systemd services, and TCP listeners, then either output a candidate inventory or, with `--apply`, merge newly found services into `configs/environments.yaml` and auto-probe common health paths such as `/healthz`, `/health`, and `/`.
When a discovered service has no confirmed HTTP health endpoint, the control plane now falls back to the best available check primitive:

- container/listener services with a discovered port become TCP-backed service checks
- systemd services without a port fall back to `systemctl is-active` over SSH
- candidates with neither a health URL, a listener port, nor a systemd unit stay in the report only and are not auto-applied

If a service is tied to a host with `services[].host`, the incident builder can suppress downstream service/dependency symptoms when that host is already down and focus notifications on the root cause.
If a service defines `services[].slo`, the scheduler/API will also emit synthetic results like `slo_availability_<service>` based on recent audit history and error-budget burn rate.

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
export OPS_ALERT_TOKEN=change-me-alerts
export OPS_ALERTMANAGER_API_TOKEN=change-me-alertmanager-api
go run ./cmd/ops-api --addr :8090 --env-file configs/environments.yaml --policy configs/policies.yaml --audit audit/api.jsonl --pending-driver sqlite --pending-file audit/pending-actions.db --pending-ttl 24h --rate-limit-window 1m --rate-limit-max 120 --notify-config configs/notifications.yaml --notify-trigger-after 2 --notify-recovery-after 2 --alertmanager-sync-ack --alertmanager-silence-duration 2h
# recommended for larger history windows and incident summaries
go run ./cmd/ops-api --addr :8090 --env-file configs/environments.yaml --policy configs/policies.yaml --audit audit/api.db --audit-driver sqlite --incident-state-file audit/incidents.db --pending-driver sqlite --pending-file audit/pending-actions.db --alertmanager-sync-ack --alertmanager-silence-duration 2h
```

Alertmanager webhook ingestion:

```yaml
receivers:
  - name: ops-agent
    webhook_configs:
      - url: http://ops-agent.internal:8090/alerts/alertmanager
        http_config:
          authorization:
            type: Bearer
            credentials: change-me-alerts
```

If an incident originated from Alertmanager and the API is started with `--alertmanager-sync-ack`, acknowledging that incident through `/incidents/ack`, Telegram `/ack`, or the LLM tool flow will also create a matching Alertmanager silence for the original alert labels.
Use `OPS_ALERTMANAGER_API_TOKEN` when your Alertmanager API requires authentication, and tune the silence window with `--alertmanager-silence-duration`.
Created silences are now stored as structured incident state and shown back in `/incidents/get`, Telegram incident detail, and timelines. You can later expire one through `/incidents/unsilence` or Telegram `/unsilence`.
`ops-api` can also periodically reconcile stored Alertmanager silence state with `--alertmanager-refresh-interval` and `--alertmanager-refresh-timeout`, so manual silence expiry or external changes eventually flow back into the local incident record. You can trigger the same refresh on demand with `POST /incidents/reconcile-alertmanager`.

Telegram ChatOps (single chat, slash commands + optional OpenAI API LLM):

```bash
export OPS_API_TOKEN=change-me
export OPS_TG_BOT_TOKEN=123456:replace-me
export OPENAI_API_KEY=<server_side_key>
# optional when using an OpenAI-compatible gateway
# export OPENAI_BASE_URL=https://your-gateway.example.com/v1
# export OPENAI_MODEL=gpt-5.4
go run ./cmd/ops-telegram --api-base http://127.0.0.1:8090 --api-token "$OPS_API_TOKEN" --bot-token "$OPS_TG_BOT_TOKEN" --chat-id <your_chat_id> --chatops-config configs/chatops.yaml --openai-api-key "$OPENAI_API_KEY" --audit audit/telegram.jsonl
```

Telegram commands:

```text
/help
/reset
/health prod
/promql prod up
/promql prod --minutes=30 --step=60s avg(rate(http_requests_total[5m]))
/stats prod
/incidents 60
/active prod
/incident <incident_id>
/timeline <incident_id> 90
/ack <incident_id> taking ownership
/unsilence <incident_id> resume notifications
/assign <incident_id> alice on it
/pending
/requests pending
/show <request_id>
/request prod restart_container --target-host=app-1 cicdtest-app
/approve <request_id>
/reject <request_id> optional reason
```

Telegram natural language:

```text
prod 现在状态怎么样
prod 过去 30 分钟请求量怎么样
prod CPU 最近是不是升高了
prod 的 incident 平均多久 ack、多久恢复
最近 2 小时有什么异常
列出 prod 的活跃事故
把 prod 那个 incident 先 ack 掉
把这个 incident 的 silence 取消掉
把 prod 那个事故分给 alice
申请重启 app-1 上的 cicdtest-app
把刚才那个审批通过
确认执行
取消
```

Quick test:

```bash
curl -s http://127.0.0.1:8090/ready
curl -s "http://127.0.0.1:8090/health/run?env=test" -H "Authorization: Bearer $OPS_API_TOKEN"
curl -s "http://127.0.0.1:8090/prometheus/query?env=test&query=up" -H "Authorization: Bearer $OPS_API_TOKEN"
curl -s "http://127.0.0.1:8090/prometheus/query?env=prod&query=avg(rate(http_requests_total%5B5m%5D))&minutes=30&step=60s" -H "Authorization: Bearer $OPS_API_TOKEN"
curl -s "http://127.0.0.1:8090/incidents/stats?project=core&env=prod" -H "Authorization: Bearer $OPS_API_TOKEN"
curl -s -X POST "http://127.0.0.1:8090/alerts/alertmanager" \
  -H "Authorization: Bearer $OPS_ALERT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"receiver":"ops-agent","commonLabels":{"env":"prod","severity":"critical"},"alerts":[{"status":"firing","fingerprint":"fp-1","labels":{"alertname":"HighErrorRate","instance":"api-1:9090"},"annotations":{"summary":"api 5xx ratio too high"},"startsAt":"2026-03-18T10:00:00Z"}]}'

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
curl -s "http://127.0.0.1:8090/actions/pending?project=core" -H "Authorization: Bearer $OPS_API_TOKEN"
curl -s "http://127.0.0.1:8090/actions/list?status=executed&limit=20" -H "Authorization: Bearer $OPS_API_TOKEN"
# cursor pagination: use next_cursor from previous response
curl -s "http://127.0.0.1:8090/actions/list?status=pending&limit=20&cursor=<next_cursor>" -H "Authorization: Bearer $OPS_API_TOKEN"
curl -s -X POST http://127.0.0.1:8090/actions/approve \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $OPS_API_TOKEN" \
  -d "{\"request_id\":\"$REQ_ID\",\"approver\":\"ops-admin\"}"

curl -s "http://127.0.0.1:8090/audit/tail?file=api.jsonl&limit=20" -H "Authorization: Bearer $OPS_API_TOKEN"
curl -s "http://127.0.0.1:8090/incidents/summary?minutes=60&project=core" -H "Authorization: Bearer $OPS_API_TOKEN"
curl -s "http://127.0.0.1:8090/incidents/active?project=core" -H "Authorization: Bearer $OPS_API_TOKEN"
curl -s "http://127.0.0.1:8090/incidents/get?id=ops-scheduler|core|prod" -H "Authorization: Bearer $OPS_API_TOKEN"
curl -s "http://127.0.0.1:8090/incidents/timeline?id=ops-scheduler|core|prod&minutes=90" -H "Authorization: Bearer $OPS_API_TOKEN"
curl -s -X POST http://127.0.0.1:8090/incidents/reconcile-alertmanager \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $OPS_API_TOKEN" \
  -d '{"project":"core","env":"prod","actor":"ops-admin"}'
curl -s -X POST http://127.0.0.1:8090/incidents/unsilence \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $OPS_API_TOKEN" \
  -d '{"id":"alertmanager|core|prod|fp-1","actor":"ops-admin","note":"resume notifications"}'
curl -s -X POST http://127.0.0.1:8090/incidents/ack \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $OPS_API_TOKEN" \
  -d '{"id":"ops-scheduler|core|prod","actor":"ops-oncall","note":"investigating"}'
curl -s -X POST http://127.0.0.1:8090/incidents/assign \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $OPS_API_TOKEN" \
  -d '{"id":"ops-scheduler|core|prod","owner":"alice","actor":"ops-lead","note":"primary responder"}'
curl -s "http://127.0.0.1:8090/metrics"
```

## Guardrails

- Supported actions come from a single action registry in `internal/actions`.
- Production guardrails apply when `env=prod` or `env=production`.
- `policies.production.require_human_approval=true` upgrades otherwise-safe actions to approval-required in production.
- `policies.production.max_auto_actions_per_hour` limits unattended production actions per hour; excess requests are converted to approval-required.
- `policies.forbidden_commands` now blocks actions whose runbook content contains a forbidden command token.
- `GET /audit/tail` only reads files inside the configured audit directory; `jsonl` stores return tail lines and `sqlite` stores return recent structured events.
- `target_host` lets `ops-worker` and `ops-api` run a runbook over SSH on a host declared under the chosen environment.
- `ops-agent discover --apply` only appends or enriches discovered services; it does not delete existing services or rewrite unrelated hosts.
- `ops-scheduler --discover-interval` runs the same discovery/apply flow on a lower cadence than health checks, so new host services can join the next health cycle without a restart.
- `host_ssh_*` remains the root-cause gate for host reachability; if SSH is already down, the incident layer suppresses dependent host resource/process checks to avoid duplicate noise.
- `service_runtime_*` and `service_logs_*` are treated as service-scoped signals, so container flapping and recent systemd error logs show up in the same incident context as the parent service.
- `/health` and `/health/run` responses now include `highlights`, which bubble the most actionable runtime/log signals to the top for Telegram and LLM consumers.
- `environments.<env>.project` adds a first-class project boundary; actions, incident summaries, and Telegram access control can now be scoped by project.
- `audit-driver sqlite` + `incident-state-file` upgrades the control plane from append-only logs to a queryable state model with active incidents, acknowledgements, and ownership.
- `environments.<env>.prometheus` lets the control plane read that environment's Prometheus as an external observability source without giving the bot write access.
- `/alerts/alertmanager` lets external Alertmanager alerts join the same incident lifecycle; a dedicated `OPS_ALERT_TOKEN` keeps that webhook isolated from the main operator API token.
- `GET /metrics` now also exports incident lifecycle gauges such as `ops_incident_open_records`, `ops_incident_reopen_total`, `ops_incident_resolution_total`, `ops_incident_avg_mtta_seconds`, and `ops_incident_avg_mttr_seconds`.
- Environment health checks run concurrently while keeping a stable output order.
- `services[].host` lets the incident layer relate service failures back to a declared host for root-cause suppression.
- `services[].slo` lets the incident layer evaluate availability burn rate over short/long windows using recent `health_run` / `health_cycle` history.

## Notifications

- `ops-scheduler` can send warn/fail health reports automatically with `--notify-webhook`, `--notify-slack-webhook`, or `--notify-telegram-bot-token` + `--notify-telegram-chat-id`.
- `ops-api` supports the same notifier flags, but `/health/run` only sends when `notify=1` is present.
- `--notify-config` loads routing rules, named receivers, silences, and maintenance windows from `configs/notifications.yaml`.
- Notification routes currently match on `env`, `source`, and `severity`, and support a default receiver fallback.
- Active silences and maintenance windows suppress notifications without stopping health checks; if an issue survives the mute window, the controller will deliver it after the window ends.
- `--notify-trigger-after` and `--notify-recovery-after` let you suppress flapping by requiring consecutive unhealthy or healthy cycles before opening or closing an incident.
- Health responses now include `summary`, `suggestions`, and `suppressed_checks` so callers can distinguish root causes from downstream symptoms.
- Acknowledged incidents now suppress duplicate follow-up notifications until the fingerprint changes again, so ownership and ack actually reduce noise instead of just adding metadata.

## ChatOps

- `cmd/ops-telegram` is a thin Telegram front-end over `ops-api`; it does not execute runbooks directly.
- Slash commands and approval buttons always work without any LLM.
- `/pending` now includes `View / Approve / Reject` inline buttons, and high-risk LLM actions expose `Confirm / Cancel` buttons as a safer alternative to free-text confirmation.
- `/active`, `/incident`, `/ack`, and `/assign` turn Telegram into a real incident room: responders can see what is currently open, acknowledge it, and claim ownership without leaving chat.
- `/stats [env]` and `GET /incidents/stats` expose lifecycle aggregates such as open count, reopen count, mean time to acknowledge, and mean time to resolve.
- `/timeline <incident_id> [minutes]` and the inline `Timeline` button let responders inspect what changed shortly before an incident opened, including likely correlated deploy/runbook changes.
- `/promql <env> ...` and the `query_prometheus` LLM tool let responders pull Prometheus metrics and recent trends into the same Telegram workflow as incidents and approvals.
- If `OPENAI_API_KEY` or `--openai-api-key` is configured, non-`/` Telegram messages are sent to the OpenAI Responses API with tool calling enabled.
- The LLM is a planner only: it can read health/incidents/pending requests and submit approve/reject/request actions through `ops-api`, so policy, approval, audit, and execution still stay in `ops-api` + `ops-worker`.
- `/requests [status]` and `/show <request_id>` make request detail lookup explicit, so operators and the LLM can inspect a concrete request before approving or rejecting it.
- State-changing natural-language operations now require a second confirmation step. The bot stores one pending confirmation per Telegram actor and only executes after the same actor replies `确认执行`; replying `取消` drops it.
- `/reset` clears the stored LLM conversation state, and slash commands or approval buttons also reset that state to avoid stale context.
- LLM tool calls and confirmation decisions are written to the Telegram audit file so model-driven actions can be traced separately from `ops-api`.
- `configs/chatops.yaml` lets you define Telegram actors with `viewer / operator / approver / admin` roles, optional per-user `allowed_actions`, denylist patterns for prompt-injection-style input, and a max input length.
- `configs/chatops.yaml` also supports `allowed_projects`, so one shared Telegram bot can safely serve multiple projects without exposing cross-project incidents or approvals.
- Restrict it with a single `--chat-id` so only one Telegram chat can interact with the control plane.
- Users do not need their own ChatGPT/OpenAI account authorization; the bot uses one server-side API key.

## SLO Trends

- Service SLOs are configured inline under `services[].slo` in [configs/environments.yaml](/Users/zhangza/code/agent/ops-agent/configs/environments.yaml).
- The current implementation tracks availability only and evaluates burn rate over two alert tiers:
  `page_short_window` + `page_long_window` against `page_burn_rate`
  `ticket_short_window` + `ticket_long_window` against `ticket_burn_rate`
- SLO evaluation uses the audit history already written by `ops-api` and `ops-scheduler`, so trend checks improve as the bot runs longer.
- Synthetic SLO results participate in incident status and notification routing, but they do not create automatic remediation suggestions by themselves.
