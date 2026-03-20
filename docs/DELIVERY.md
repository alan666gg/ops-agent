# Delivery Guide

This project is now packaged for two deployment styles:

- `docker compose` for fast evaluation and smaller teams
- `systemd` for a dedicated Linux control plane host

## Prerequisites

- Fill [environments.yaml](/Users/zhangza/code/agent/ops-agent/configs/environments.yaml), [policies.yaml](/Users/zhangza/code/agent/ops-agent/configs/policies.yaml), [notifications.yaml](/Users/zhangza/code/agent/ops-agent/configs/notifications.yaml), and [chatops.yaml](/Users/zhangza/code/agent/ops-agent/configs/chatops.yaml)
- Put a usable SSH key on the control-plane host if you want remote discovery, SSH host checks, or remote runbooks
- Export the tokens in [ops-agent.env.example](/Users/zhangza/code/agent/ops-agent/deploy/ops-agent.env.example)

## Docker Compose

1. Copy `deploy/ops-agent.env.example` to `.env` and fill the secrets.
2. Make sure `audit/` exists on the host.
3. If you need SSH, uncomment the `OPS_SSH_DIR` bind mount in [docker-compose.yaml](/Users/zhangza/code/agent/ops-agent/deploy/docker-compose.yaml).
4. Start the stack:

```bash
cd deploy
docker compose up -d --build
```

5. Run a smoke test from the same repo:

```bash
export OPS_API_TOKEN=change-me
go run ./cmd/ops-agent smoke --api-base http://127.0.0.1:8090 --api-token "$OPS_API_TOKEN" --env prod --env-file configs/environments.yaml
```

## systemd

1. Build or copy the binaries to `/usr/local/bin/`.
2. Copy config files to `/etc/ops-agent/`.
3. Copy `deploy/ops-agent.env.example` to `/etc/ops-agent/ops-agent.env` and fill it.
4. Copy [ops-api.service](/Users/zhangza/code/agent/ops-agent/deploy/systemd/ops-api.service), [ops-scheduler.service](/Users/zhangza/code/agent/ops-agent/deploy/systemd/ops-scheduler.service), and [ops-telegram.service](/Users/zhangza/code/agent/ops-agent/deploy/systemd/ops-telegram.service) to `/etc/systemd/system/`.
5. Create `/var/lib/ops-agent/` and place the SSH key under the `ops-agent` user when remote execution is needed.
6. Enable the services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ops-api ops-scheduler ops-telegram
```

## Acceptance Checklist

- `go run ./cmd/ops-agent validate --env-file configs/environments.yaml --policy configs/policies.yaml --notify-config configs/notifications.yaml --chatops-config configs/chatops.yaml`
- `go run ./cmd/ops-agent smoke --api-base http://127.0.0.1:8090 --api-token "$OPS_API_TOKEN" --env prod --env-file configs/environments.yaml`
- `curl -fsS http://127.0.0.1:8090/ready`
- `curl -fsS http://127.0.0.1:8090/metrics | head`
- Telegram `/health <env>` works
- One approval-required action can be created and approved end-to-end
