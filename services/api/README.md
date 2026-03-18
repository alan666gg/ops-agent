# API service

Minimal HTTP API for running health checks, policy-gated actions, and reading audit tail.

Run:

```bash
export OPS_API_TOKEN=change-me
go run ./cmd/ops-api --addr :8090 --env-file configs/environments.yaml --policy configs/policies.yaml --audit audit/api.jsonl
```

Endpoints:

- `GET /ready` (no token)
- `GET /health/run?env=test` (Bearer token)
- `POST /actions/run` (Bearer token; direct mode)
- `POST /actions/request` (Bearer token; creates approval ticket)
- `GET /actions/pending` (Bearer token)
- `GET /actions/list?status=pending|executed|failed|denied|expired` (Bearer token)
- `POST /actions/approve` (Bearer token)
- `POST /actions/reject` (Bearer token)
- `GET /audit/tail?limit=50` (Bearer token)
- `GET /incidents/summary?minutes=60` (Bearer token)

OpenAPI draft: `docs/openapi.yaml`
