# ops-agent

Internal Ops Agent (v0.1) scaffold.

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
go run ./cmd/ops-agent policy --action restart_container --policy configs/policies.yaml --audit audit/events.jsonl
```

Scheduler (periodic health checks):

```bash
go run ./cmd/ops-scheduler --env test --env-file configs/environments.yaml --audit audit/scheduler.jsonl --once
```

Worker (policy-gated runbook execution):

```bash
# low-risk action (allowed)
go run ./cmd/ops-worker --action check_host_health --policy configs/policies.yaml --audit audit/worker.jsonl

# action requiring approval
go run ./cmd/ops-worker --action restart_container --args cicdtest-app --policy configs/policies.yaml --audit audit/worker.jsonl --approved
```

API (minimal control plane):

```bash
go run ./cmd/ops-api --addr :8090 --env-file configs/environments.yaml --policy configs/policies.yaml --audit audit/api.jsonl
```

Quick test:

```bash
curl -s http://127.0.0.1:8090/ready
curl -s "http://127.0.0.1:8090/health/run?env=test"
curl -s -X POST http://127.0.0.1:8090/actions/run \
  -H 'Content-Type: application/json' \
  -d '{"action":"check_host_health","approved":true,"actor":"local-dev"}'
```

