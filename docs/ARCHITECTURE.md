# Architecture (v0.1)

- Scheduler triggers periodic checks.
- Worker executes runbooks with policy guardrails.
- API exposes health/incidents/actions.
- All actions are audited.

Flow:
1. detect issue
2. classify severity
3. suggest action
4. require approval if risky
5. execute runbook
6. audit + notify
