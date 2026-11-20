# RT Editions

RT is developed under an **open-core** model. The Community Edition in this
repository is free and open source under the [Apache License 2.0](LICENSE). RT
Enterprise adds the production edge, scale-out persistence, client-ready
reporting, and a supported appliance on top of the same core.

| Capability | Community (this repo, Apache-2.0) | Enterprise |
|---|---|---|
| Engagement graph (findings + tasks) | ✅ | ✅ |
| Signed Rules-of-Engagement scope (Python ↔ Go verified) | ✅ | ✅ |
| Operator-gated exploitation (`exploit`/`post`/`destructive`) | ✅ | ✅ |
| Durable engagement loop — pause at gate / resume (`rt run`) | ✅ | ✅ |
| Go policy-gate + egress proxy (physical scope boundary) | ✅ | ✅ |
| Tool sandbox + adapter contract (nmap/nuclei examples) | ✅ | ✅ |
| Tamper-evident hash-chained audit log (SQLite) | ✅ | ✅ |
| Single-appliance operator console (`rt serve`, loopback) | ✅ | ✅ |
| Markdown VAPT report generator | ✅ | ✅ |
| **Production gateway** — auth, SSO, TLS, multi-user, multi-engagement | — | ✅ |
| **Scale-out persistence** — Postgres + Neo4j attack-graph queries | — | ✅ |
| **Branded reporting** — client report templates, compliance mapping | — | ✅ |
| **Supported appliance** — hardened OVA/ISO, gVisor sandbox, updates, SLA | — | ✅ |

The line is drawn so the Community Edition is a complete, self-hosted tool for
a single operator running authorized engagements. Enterprise is for firms
running many operators and engagements who need a hardened, supported,
multi-tenant deployment.

The Community console binds to loopback and has no authentication by design —
on a single appliance the operator opens it directly or over an SSH tunnel.
Exposing RT to multiple users or the network is what the Enterprise gateway is
for.

Enterprise enquiries: **sales@hexalab.tech** (or see https://hexalab.tech/rt).
