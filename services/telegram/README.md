# Telegram service

Telegram ChatOps entrypoint for `ops-agent`.

Run:

```bash
export OPS_API_TOKEN=change-me
export OPS_TG_BOT_TOKEN=123456:replace-me
go run ./cmd/ops-telegram --api-base http://127.0.0.1:8090 --api-token "$OPS_API_TOKEN" --bot-token "$OPS_TG_BOT_TOKEN" --chat-id <telegram_chat_id>
```

Current behavior:

- Long-polls Telegram with `getUpdates`
- Restricts interaction to a single `--chat-id`
- Calls `ops-api` for health, incidents, pending approvals, approvals, rejections, and action requests
- Renders inline `Approve` / `Reject` buttons for pending approval items

Supported commands:

- `/help`
- `/health <env>`
- `/incidents [minutes]`
- `/pending`
- `/request <env> <action> [--target-host=name] [args...]`
- `/approve <request_id>`
- `/reject <request_id> [reason]`
