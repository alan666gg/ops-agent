# API service

Minimal HTTP API for running health checks, policy-gated actions, approvals, and bounded audit tail reads.

Run:

```bash
export OPS_API_TOKEN=change-me
go run ./cmd/ops-api --addr :8090 --env-file configs/environments.yaml --policy configs/policies.yaml --audit audit/api.jsonl
```

Endpoints:

- `GET /ready` (no token)
- `GET /metrics` (no token, Prometheus text format)
- `GET /health/run?env=test` (Bearer token)
- `POST /actions/run` (Bearer token; direct mode; request body supports `env`)
- `POST /actions/request` (Bearer token; creates approval ticket; request body supports `env`)
- `GET /actions/pending` (Bearer token)
- `GET /actions/list?status=pending|executed|failed|denied|expired` (Bearer token)
- `POST /actions/approve` (Bearer token)
- `POST /actions/reject` (Bearer token)
- `GET /audit/tail?file=api.jsonl&limit=50` (Bearer token; only `.jsonl` files in the audit dir)
- `GET /incidents/summary?minutes=60` (Bearer token)

OpenAPI draft: `docs/openapi.yaml`
