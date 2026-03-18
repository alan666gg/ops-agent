# Architecture

- Scheduler triggers periodic checks.
- Worker executes runbooks with policy guardrails and environment-aware approval checks.
- API exposes health/incidents/actions and approval workflows.
- Telegram ChatOps is a thin interaction layer over the API and does not bypass policy or approval checks.
- Telegram can optionally add an OpenAI Responses API tool-calling layer for natural-language requests, but the model still acts only through `ops-api`.
- Natural-language state-changing actions use a second confirmation step and per-actor state files so one operator's LLM context or pending confirmation does not leak into another's.
- Telegram RBAC and prompt-injection guards now sit in front of both slash commands and LLM tool calls, so actor authorization is enforced before the control plane sees a mutating request.
- Telegram request handling now has an explicit detail layer: operators can fetch one request by id before approving, and both pending approvals and LLM confirmations expose inline buttons to reduce ambiguous free-text actions.
- All actions are audited.
- Action definitions are centralized in a shared registry.
- Runbooks execute locally by default and can be sent over SSH to a configured environment host.
- Environment health checks cover local agent basics, configured host SSH reachability, service endpoints, and dependencies.
- Policy evaluation can deny an action when its runbook content matches a configured forbidden command token.
- Health incidents can be summarized into action suggestions and sent through webhook, Slack, or Telegram notifiers.
- Notification state is persisted so duplicate incidents, flapping checks, and recoveries can be handled with consecutive-sample thresholds.
- Routed notification config can suppress alerts with explicit silences or maintenance windows while still evaluating checks underneath.
- Incident aggregation is topology-aware: host reachability failures can inhibit downstream service/dependency symptoms so operators see root cause first.
- Services can define availability SLOs so the control plane emits burn-rate trend checks from recent health history, not just point-in-time probes.

Flow:
1. detect issue
2. classify severity
3. select a registered action
4. evaluate environment policy and recent auto-action budget
5. require approval if risky or production policy says so
6. execute runbook
7. audit + notify
