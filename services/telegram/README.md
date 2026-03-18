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
go run ./cmd/ops-telegram --api-base http://127.0.0.1:8090 --api-token "$OPS_API_TOKEN" --bot-token "$OPS_TG_BOT_TOKEN" --chat-id <telegram_chat_id> --chatops-config configs/chatops.yaml --openai-api-key "$OPENAI_API_KEY" --audit audit/telegram.jsonl
```

Current behavior:

- Long-polls Telegram with `getUpdates`
- Restricts interaction to a single `--chat-id`
- Calls `ops-api` for health, incidents, pending approvals, approvals, rejections, and action requests
- Calls `ops-api` for active incident lifecycle too, including acknowledge and owner assignment
- Renders inline `Approve` / `Reject` buttons for pending approval items
- Uses OpenAI Responses API tool calling for non-`/` natural-language messages when `OPENAI_API_KEY` is configured
- Keeps slash commands as a fallback and resets LLM context whenever a slash command or approval button is used
- Stores one pending natural-language confirmation per Telegram actor, so state-changing actions require the same actor to reply `确认执行` before they are sent to `ops-api`
- Writes LLM tool calls and confirmation events to the Telegram audit file
- Can enforce actor-level RBAC and input deny patterns from `configs/chatops.yaml`
- Surfaces incident `highlights` first in `/health` replies so runtime signals like `CONTAINER_OOMKILLED` or recent systemd errors are visible before the longer result list

Supported commands:

- `/help`
- `/reset`
- `/health <env>`
- `/incidents [minutes]`
- `/active [env]`
- `/incident <incident_id>`
- `/ack <incident_id> [note]`
- `/assign <incident_id> <owner> [note]`
- `/pending`
- `/requests [status]`
- `/show <request_id>`
- `/request <env> <action> [--target-host=name] [args...]`
- `/approve <request_id>`
- `/reject <request_id> [reason]`

Natural-language examples:

- `prod 现在状态怎么样`
- `最近 2 小时有什么异常`
- `列出 prod 的活跃事故`
- `先 ack 掉 prod 那个 incident`
- `把 prod 那个事故分给 alice`
- `申请重启 app-1 上的 cicdtest-app`
- `把刚才那个审批通过`
- `确认执行`
- `取消`

Interaction notes:

- `/pending` now renders `View / Approve / Reject` buttons for each visible request
- `/active` now renders `View / Ack / Claim` buttons for each visible incident
- High-risk LLM-created operations render `Confirm / Cancel` buttons backed by the same pending confirmation store as the text replies
- `/show <request_id>` returns one request's full detail and, if it is still pending, renders approve/reject buttons for that exact request
- `/incident <incident_id>` returns one incident's detail and, if it is still open, renders ack/claim buttons for that exact incident
