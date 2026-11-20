# Operator console (placeholder)

The operator-facing UI for RT. Planned (TS/React), backed by `gateway/`:

- engagement dashboard (objective, scope, status)
- live attack graph (findings + tasks)
- **approval queue** — the human gate: review and confirm/deny exploit-tier
  tasks (`GET /api/approvals`, `POST /api/approve`)
- report preview/export

The single-appliance backend now exists: `rt serve` (see
`orchestrator/rt/serve.py`) is a stdlib JSON API over one engagement graph —
`GET /api/engagement|graph|approvals`, `POST /api/approve` (→ `rt confirm`, with
the approval written to the hash-chained audit log), and `GET /api/audit/verify`.
It binds loopback by default; the Go `gateway/` fronts it in production (auth,
TLS, multi-engagement). The UI (TS/React) is still to be built against these
endpoints.
