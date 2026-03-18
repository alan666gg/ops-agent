# Telegram service

Telegram ChatOps entrypoint for `ops-agent`.

Run:

```bash
export OPS_API_TOKEN=change-me
export OPS_TG_BOT_TOKEN=123456:replace-me
export OPENAI_API_KEY=<server_side_key>
# optional for an OpenAI-compatible gateway
# export OPENAI_BASE_URL=https://your-gateway.example.com/v1
# export OPENAI_MODEL=gpt-5-mini
go run ./cmd/ops-telegram --api-base http://127.0.0.1:8090 --api-token "$OPS_API_TOKEN" --bot-token "$OPS_TG_BOT_TOKEN" --chat-id <telegram_chat_id> --openai-api-key "$OPENAI_API_KEY"
```

Current behavior:

- Long-polls Telegram with `getUpdates`
- Restricts interaction to a single `--chat-id`
- Calls `ops-api` for health, incidents, pending approvals, approvals, rejections, and action requests
- Renders inline `Approve` / `Reject` buttons for pending approval items
- Uses OpenAI Responses API tool calling for non-`/` natural-language messages when `OPENAI_API_KEY` is configured
- Keeps slash commands as a fallback and resets LLM context whenever a slash command or approval button is used

Supported commands:

- `/help`
- `/reset`
- `/health <env>`
- `/incidents [minutes]`
- `/pending`
- `/request <env> <action> [--target-host=name] [args...]`
- `/approve <request_id>`
- `/reject <request_id> [reason]`

Natural-language examples:

- `prod 现在状态怎么样`
- `最近 2 小时有什么异常`
- `申请重启 app-1 上的 cicdtest-app`
- `把刚才那个审批通过`
