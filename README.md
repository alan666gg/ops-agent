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

Host discovery (Docker + systemd + listening ports over SSH):

```bash
go run ./cmd/ops-agent discover --env-file configs/environments.yaml --env prod --host app-1 --format yaml
# optional file output
go run ./cmd/ops-agent discover --env-file configs/environments.yaml --env prod --host app-1 --format json --out audit/discovery-app-1.json
# one-step onboarding: discover container services, probe health URLs, and write back into environments.yaml
go run ./cmd/ops-agent discover --env-file configs/environments.yaml --env prod --host app-1 --apply
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
- optional history-backed SLO burn-rate checks from `services[].slo`

Service discovery is now a low-frequency companion step to the scheduler. `ops-agent discover` can SSH into a declared host, list Docker containers, running systemd services, and TCP listeners, then either output a candidate inventory or, with `--apply`, merge newly found container services into `configs/environments.yaml` and auto-probe common health paths such as `/healthz`, `/health`, and `/`.

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
go run ./cmd/ops-api --addr :8090 --env-file configs/environments.yaml --policy configs/policies.yaml --audit audit/api.jsonl --pending-driver sqlite --pending-file audit/pending-actions.db --pending-ttl 24h --rate-limit-window 1m --rate-limit-max 120 --notify-config configs/notifications.yaml --notify-trigger-after 2 --notify-recovery-after 2
```

Telegram ChatOps (single chat, slash commands + optional OpenAI API LLM):

```bash
export OPS_API_TOKEN=change-me
export OPS_TG_BOT_TOKEN=123456:replace-me
export OPENAI_API_KEY=<server_side_key>
# optional when using an OpenAI-compatible gateway
# export OPENAI_BASE_URL=https://your-gateway.example.com/v1
# export OPENAI_MODEL=gpt-5-mini
go run ./cmd/ops-telegram --api-base http://127.0.0.1:8090 --api-token "$OPS_API_TOKEN" --bot-token "$OPS_TG_BOT_TOKEN" --chat-id <your_chat_id> --chatops-config configs/chatops.yaml --openai-api-key "$OPENAI_API_KEY" --audit audit/telegram.jsonl
```

Telegram commands:

```text
/help
/reset
/health prod
/incidents 60
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
最近 2 小时有什么异常
申请重启 app-1 上的 cicdtest-app
把刚才那个审批通过
确认执行
取消
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
- `ops-agent discover --apply` only appends or enriches discovered container services; it does not delete existing services or rewrite unrelated hosts.
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

## ChatOps

- `cmd/ops-telegram` is a thin Telegram front-end over `ops-api`; it does not execute runbooks directly.
- Slash commands and approval buttons always work without any LLM.
- `/pending` now includes `View / Approve / Reject` inline buttons, and high-risk LLM actions expose `Confirm / Cancel` buttons as a safer alternative to free-text confirmation.
- If `OPENAI_API_KEY` or `--openai-api-key` is configured, non-`/` Telegram messages are sent to the OpenAI Responses API with tool calling enabled.
- The LLM is a planner only: it can read health/incidents/pending requests and submit approve/reject/request actions through `ops-api`, so policy, approval, audit, and execution still stay in `ops-api` + `ops-worker`.
- `/requests [status]` and `/show <request_id>` make request detail lookup explicit, so operators and the LLM can inspect a concrete request before approving or rejecting it.
- State-changing natural-language operations now require a second confirmation step. The bot stores one pending confirmation per Telegram actor and only executes after the same actor replies `确认执行`; replying `取消` drops it.
- `/reset` clears the stored LLM conversation state, and slash commands or approval buttons also reset that state to avoid stale context.
- LLM tool calls and confirmation decisions are written to the Telegram audit file so model-driven actions can be traced separately from `ops-api`.
- `configs/chatops.yaml` lets you define Telegram actors with `viewer / operator / approver / admin` roles, optional per-user `allowed_actions`, denylist patterns for prompt-injection-style input, and a max input length.
- Restrict it with a single `--chat-id` so only one Telegram chat can interact with the control plane.
- Users do not need their own ChatGPT/OpenAI account authorization; the bot uses one server-side API key.

## SLO Trends

- Service SLOs are configured inline under `services[].slo` in [configs/environments.yaml](/Users/zhangza/code/agent/ops-agent/configs/environments.yaml).
- The current implementation tracks availability only and evaluates burn rate over two alert tiers:
  `page_short_window` + `page_long_window` against `page_burn_rate`
  `ticket_short_window` + `ticket_long_window` against `ticket_burn_rate`
- SLO evaluation uses the audit history already written by `ops-api` and `ops-scheduler`, so trend checks improve as the bot runs longer.
- Synthetic SLO results participate in incident status and notification routing, but they do not create automatic remediation suggestions by themselves.
