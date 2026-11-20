# Changelog

All notable changes to RT (Community Edition) are documented here. The format
is based on [Keep a Changelog](https://keepachangelog.com/), and RT adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-11-20

First public release of the RT Community Edition.

### Added
- **Engagement graph** — Finding nodes and Task hyper-edges along the kill
  chain, persisted as fcntl-locked JSON on disk (crash-safe, no database
  required for the core loop).
- **Signed scope (Rules of Engagement)** — allowed/excluded CIDRs and domains,
  time window and rate cap, signed by the operator. Python signer and Go
  verifier produce byte-identical canonical forms, so a scope signed in Python
  verifies in the Go policy-gate.
- **Operator-gated exploitation** — `exploit`, `post`, and `destructive` tasks
  are blocked until an operator runs `rt confirm`, enforced in the store *and*
  re-checked in the Go sandbox, not in a prompt.
- **Durable engagement loop** (`rt run`) — auto-dispatches ready tasks, pauses
  at the operator gate, resumes after confirmation, and recovers from a crash
  because all state is on disk.
- **Go policy-gate + egress proxy** — authoritative scope enforcement and a
  network-layer egress boundary that fails closed: a tool's only route is the
  proxy, which refuses out-of-scope destinations.
- **Tool sandbox + adapter contract** — with nmap/nuclei example adapters, each
  taking its target only from the authorized field.
- **Tamper-evident audit log** — every operator approval and agent action
  chained by SHA-256; `rt audit verify` detects any edit, deletion, or reorder.
  SQLite backend by default.
- **Operator console** (`rt serve`) — a stdlib web UI for a single appliance:
  findings by severity, the task graph, the live approval queue, and the audit
  chain-integrity badge. Binds to loopback.
- **VAPT report generator** — `rt report` renders the engagement graph to a
  Markdown report.
- **Appliance packaging** — Dockerfiles for each service, a Compose file, and
  an `install.sh` for a single-host self-hosted deployment.

### Licensing
- Community Edition released under the **Apache License 2.0**.
- Orchestration-core portions derived from the MIT-licensed
  [sapper-v2](https://github.com/N1nEmAn/sapper-v2) retain their MIT notice; see
  [`NOTICE`](NOTICE) and [`LICENSE-THIRD-PARTY`](LICENSE-THIRD-PARTY).

[0.1.0]: https://github.com/EaH696/RT/releases/tag/v0.1.0
