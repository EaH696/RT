# Operator console (placeholder)

The operator-facing UI for RT. Planned (TS/React), backed by `gateway/`:

- engagement dashboard (objective, scope, status)
- live attack graph (findings + tasks)
- **approval queue** — the human gate: review and confirm/deny exploit-tier
  tasks (`GET /api/approvals`, `POST /api/approve`)
- report preview/export

Not yet implemented — this scaffold ships the CLI (`rt`) and the gateway API
stub it will build on.
