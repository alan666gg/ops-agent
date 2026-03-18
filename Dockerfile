# syntax=docker/dockerfile:1

FROM golang:1.26-bookworm AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o /out/ops-api ./cmd/ops-api && \
    CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o /out/ops-scheduler ./cmd/ops-scheduler && \
    CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o /out/ops-worker ./cmd/ops-worker

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl bash && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /out/ops-api /usr/local/bin/ops-api
COPY --from=builder /out/ops-scheduler /usr/local/bin/ops-scheduler
COPY --from=builder /out/ops-worker /usr/local/bin/ops-worker
COPY configs ./configs
COPY runbooks ./runbooks
RUN mkdir -p /app/audit && chmod +x /app/runbooks/*.sh
EXPOSE 8090
ENV OPS_API_TOKEN=""
CMD ["ops-api", "--addr", ":8090", "--env-file", "configs/environments.yaml", "--policy", "configs/policies.yaml", "--audit", "audit/api.jsonl", "--pending-driver", "sqlite", "--pending-file", "audit/pending-actions.db"]
