# Architecture

- Scheduler triggers periodic checks.
- Worker executes runbooks with policy guardrails and environment-aware approval checks.
- API exposes health/incidents/actions and approval workflows.
- All actions are audited.
- Action definitions are centralized in a shared registry.

Flow:
1. detect issue
2. classify severity
3. select a registered action
4. evaluate environment policy and recent auto-action budget
5. require approval if risky or production policy says so
6. execute runbook
7. audit + notify
