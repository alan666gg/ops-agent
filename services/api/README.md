# API service

Minimal HTTP API for running health checks, policy-gated actions, and reading audit tail.

Run:

```bash
go run ./cmd/ops-api --addr :8090 --env-file configs/environments.yaml --policy configs/policies.yaml --audit audit/api.jsonl
```

Endpoints:

- `GET /ready`
- `GET /health/run?env=test`
- `POST /actions/run`
- `GET /audit/tail?limit=50`
