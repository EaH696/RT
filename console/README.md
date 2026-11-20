# Operator console (placeholder)

The operator-facing UI for RT. Planned (TS/React), backed by `gateway/`:

- engagement dashboard (objective, scope, status)
- live attack graph (findings + tasks)
- **approval queue** — the human gate: review and confirm/deny exploit-tier
  tasks (`GET /api/approvals`, `POST /api/approve`)
- report preview/export

## Backend

`rt serve` (`orchestrator/rt/serve.py`) is a stdlib JSON API over one engagement
graph — `GET /api/engagement|graph|approvals`, `POST /api/approve` (→ `rt
confirm`, written to the hash-chained audit log), and `GET /api/audit/verify`.
It binds loopback; the Go `gateway/` fronts it (auth, TLS, multi-engagement).

## UI — `index.html`

A single self-contained page (vanilla JS, no build step, no CDN, no external
fonts) so it runs on an air-gapped appliance. The gateway serves it same-origin
with `-console console/index.html`, so its API calls reach the same host with no
CORS. Features: token sign-in, engagement picker, summary tiles, the live
approval queue with one-click confirm, findings/tasks tables, and the audit
chain-integrity badge. Approvals send only `task_id` — the gateway stamps the
operator identity from the authenticated token, so the audit records who really
approved. A richer TS/React build can replace this later against the same
endpoints.
