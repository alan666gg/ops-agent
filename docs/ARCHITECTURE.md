# Architecture

- Scheduler triggers periodic checks.
- Worker executes runbooks with policy guardrails and environment-aware approval checks.
- API exposes health/incidents/actions and approval workflows.
- All actions are audited.
- Action definitions are centralized in a shared registry.
- Runbooks execute locally by default and can be sent over SSH to a configured environment host.
- Environment health checks cover local agent basics, configured host SSH reachability, service endpoints, and dependencies.
- Policy evaluation can deny an action when its runbook content matches a configured forbidden command token.

Flow:
1. detect issue
2. classify severity
3. select a registered action
4. evaluate environment policy and recent auto-action budget
5. require approval if risky or production policy says so
6. execute runbook
7. audit + notify
