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

