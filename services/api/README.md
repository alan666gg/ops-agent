# API service

Minimal HTTP API for running health checks, policy-gated actions, approvals, and bounded audit tail reads.

For packaged deployment examples, see [Delivery Guide](/Users/zhangza/code/agent/ops-agent/docs/DELIVERY.md).

Run:

```bash
export OPS_API_TOKEN=change-me
export OPS_ALERT_TOKEN=change-me-alerts
export OPS_CHANGE_TOKEN=change-me-changes
export OPS_ALERTMANAGER_API_TOKEN=change-me-alertmanager-api
go run ./cmd/ops-api --addr :8090 --env-file configs/environments.yaml --policy configs/policies.yaml --audit audit/api.db --audit-driver sqlite --incident-state-file audit/incidents.db --notify-config configs/notifications.yaml --notify-trigger-after 2 --notify-recovery-after 2 --alertmanager-sync-ack --alertmanager-silence-duration 2h --alertmanager-refresh-interval 5m --change-token "$OPS_CHANGE_TOKEN"
```

Smoke test after startup:

```bash
go run ./cmd/ops-agent smoke --api-base http://127.0.0.1:8090 --api-token "$OPS_API_TOKEN" --env prod --env-file configs/environments.yaml
```

Endpoints:

- `GET /ready` (no token)
- `GET /metrics` (no token, Prometheus text format)
- `GET /health/run?env=test` (Bearer token)
- `GET /prometheus/query?env=prod&query=up` (Bearer token)
- `POST /changes/events` (Bearer token; ingest external deploy/change events)
- `POST /changes/github` (Bearer main API token or dedicated `OPS_CHANGE_TOKEN`)
- `POST /changes/gitlab` (Bearer main API token or dedicated `OPS_CHANGE_TOKEN`)
- `GET /changes/recent?project=core&env=prod&minutes=120` (Bearer token)
- `POST /alerts/alertmanager` (Bearer token from `OPS_ALERT_TOKEN` or the main API token)
- `POST /actions/run` (Bearer token; direct mode; request body supports `env` and optional `target_host`)
- `POST /actions/request` (Bearer token; creates approval ticket; request body supports `env` and optional `target_host`)
- `GET /actions/pending` (Bearer token)
- `GET /actions/get?id=<request_id>` (Bearer token)
- `GET /actions/list?status=pending|executed|failed|denied|expired` (Bearer token)
- `POST /actions/approve` (Bearer token)
- `POST /actions/reject` (Bearer token)
- `GET /audit/tail?file=api.jsonl&limit=50` (Bearer token; only `.jsonl` files in the audit dir)
- `GET /incidents/summary?minutes=60` (Bearer token)
- `GET /incidents/stats?project=core&env=prod` (Bearer token)
- `GET /incidents/active?project=core&env=prod` (Bearer token)
- `GET /incidents/get?id=<incident_id>` (Bearer token)
- `GET /incidents/timeline?id=<incident_id>&minutes=90` (Bearer token)
- `POST /incidents/ack` (Bearer token)
- `POST /incidents/reconcile-alertmanager` (Bearer token)
- `POST /incidents/unsilence` (Bearer token)
- `POST /incidents/assign` (Bearer token)

OpenAPI draft: `docs/openapi.yaml`

If `target_host` is provided, the API resolves that host from the selected environment and runs the runbook over SSH.
If the selected environment declares `prometheus.base_url`, `GET /prometheus/query` proxies read-only PromQL queries through that environment's Prometheus.
`POST /changes/events` lets CI/CD or manual tooling push deploy and change markers into the audit stream so incident timelines can correlate outages with nearby external changes. `POST /changes/github` and `POST /changes/gitlab` accept provider webhook payloads directly and map them into the same change stream, optionally using `?env=prod` when the payload does not carry environment context. `GET /changes/recent` returns the latest change-classified entries across the same audit backend, including structured `reference`, `revision`, and `url` fields so chatops and incident timelines can show release tags, commit SHAs, and pipeline links without reparsing the message body.
`POST /alerts/alertmanager` accepts Alertmanager webhook payloads and turns each external alert into an incident record, so external Prometheus alerts share the same acknowledge/assign timeline as native bot incidents.
Incident detail responses now include structured `external` and `silence` state for Alertmanager-backed incidents.

`GET /health/run` includes local host basics, configured host SSH reachability, service health URLs, and dependency checks for the selected environment.
If a service declares `host`, the response can suppress downstream service symptoms when that host is already the active root cause.
If a service declares `slo`, the response can also include synthetic `slo_availability_*` results based on recent audit history.
`GET /health/run` now also returns `recent_changes`, triggered `metric_signals`, and strategy-tagged `suggestions`, so callers can tell apart restart candidates, likely release regressions, dependency checks, and host-capacity investigations.
If `environments.<env>.prometheus.signals` is configured, the API evaluates those read-only PromQL signals during `/health/run` and folds matching capacity/regression hints back into remediation strategy selection.
If the API is started with notifier flags, `/health/run?...&notify=1` also sends the incident summary when the status is `warn` or `fail`.
`--incident-state-file` persists active incident state, acknowledgement, owner, and notes; the same store powers `/incidents/active`, `/incidents/get`, `/incidents/timeline`, `/incidents/ack`, and `/incidents/assign`.
`GET /incidents/stats` summarizes lifecycle state from the incident store, including open/resolved counts, reopen totals, MTTA, and MTTR, optionally scoped by `project`, `env`, or `source`.
Acknowledged incidents suppress duplicate notify repeats until the fingerprint changes again.
`GET /incidents/timeline` correlates recent audit events around one incident and highlights likely change events, such as deploy/runbook actions shortly before the incident first appeared.
`GET /prometheus/query` supports instant queries by default, or range queries when `minutes` is set. `step` is optional and defaults to an auto-selected resolution.
For Alertmanager, use a dedicated `OPS_ALERT_TOKEN` so webhook senders do not need the broader operator API token.
If `--alertmanager-sync-ack` is enabled, acknowledging an Alertmanager-backed incident also creates an Alertmanager silence for the alert's original labels. Use `OPS_ALERTMANAGER_API_TOKEN` when the Alertmanager API itself requires auth.
`--alertmanager-refresh-interval` periodically re-reads stored Alertmanager silences and updates local incident state if the silence was expired or changed externally. `POST /incidents/reconcile-alertmanager` runs the same reconciliation on demand, optionally scoped by `project`, `env`, or one incident `id`.
`POST /incidents/unsilence` expires one stored Alertmanager silence and updates the same incident record so Telegram and timeline views immediately show `silence=expired`.
`GET /metrics` now exports both API traffic counters and incident lifecycle gauges, including global and per-scope open/silenced counts plus average MTTA/MTTR.
`--notify-config` replaces direct notifier flags with a routed notification policy that supports named receivers, silences, and maintenance windows.
`--notify-trigger-after` and `--notify-recovery-after` help suppress flapping by requiring consecutive unhealthy or healthy samples before opening or closing an incident.
