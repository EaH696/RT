# RT — Security model

RT is a self-hosted, semi-autonomous, **operator-gated** agentic penetration-
testing platform. Its design premise is that an autonomous offensive agent is
only safe to field if the safety controls are enforced by compiled, auditable
components — not by asking a language model to behave. This document is the
security model for a technical reviewer: the threat model, each control and how
it is enforced in code, and an honest statement of what is live versus designed-
and-pending.

## Threat model

RT drives real offensive tools against real client assets under a signed
authorization. The things that must not happen:

1. **Out-of-scope action.** A tool reaches an asset the client did not authorize
   — whether through an agent mistake, a prompt-injection from a target, or a
   compromised tool.
2. **Unapproved exploitation.** An offensive (exploit/post/destructive) action
   runs without a human operator approving it.
3. **Testing outside the agreed limits.** Activity outside the contracted time
   window or above the agreed rate.
4. **Non-repudiable gap.** An action that cannot be proven, after the fact, to
   have been authorized — the VAPT liability exposure.
5. **Key compromise.** The operator's authorization key is readable or forgeable.

The adversary model explicitly includes RT's *own* agents: target output is
treated as untrusted data (a discipline inherited verbatim from the sapper-v2
templates RT is built on), and the enforcement points assume an agent may be
confused or hostile.

## Controls

| # | Control | Enforced by | Where | Status |
|---|---------|-------------|-------|--------|
| 1 | Signed Rules of Engagement (scope) | Ed25519 signature over a canonical scope body; verified in the Go gate; unsigned/invalid refuses to start | `orchestrator/rt/scope.py`, `policy-gate/scope.go` | **Live** |
| 2 | Trust anchor | Gate accepts only signing keys in a provisioned trust store; a crypto-valid signature from an unknown key is still rejected | `policy-gate` (`VerifyTrusted`, `-trust`) | **Live** |
| 3 | Operator key custody | Pluggable signer: HSM (PKCS#11 `CKM_EDDSA`) or external signing command — key never in RT; seed-file only for dev | `orchestrator/rt/signing.py`, `docs/SIGNING.md` | **Live** (HSM/PKCS#11 path untested in CI — no token) |
| 4 | Scope enforcement (logical) | Orchestrator checks each target before dispatch; the Go policy-gate re-checks authoritatively | `scope.py`, `policy-gate` | **Live** |
| 5 | Scope enforcement (physical) | Each tool runs in an ephemeral guest whose only network route is the gate's egress proxy (netns + nftables default-drop + transparent redirect, fail-closed) | `sandbox/runtime.go` (seam), `docs/EGRESS.md` | **Designed; seam + fail-closed stub live; kernel path pending a runtime host** |
| 6 | Operator-gated exploitation | exploit/post/destructive tasks set `requires_confirmation`; not claimable until `rt confirm`; the sandbox refuses a gated tool unless the request is confirmed; the runner refuses gated tiers on a non-isolated runtime | `store.py`, `sandbox/runner.go` | **Live** |
| 7 | Testing time window | Gate denies every target outside `[window_start, window_end]`; malformed window fails closed | `policy-gate/scope.go` (`withinWindow`) | **Live** |
| 8 | Rate cap (`max_rps`) | Per-host token bucket at the gate; checked only for in-scope targets so probes can't exhaust budget | `policy-gate/rate.go` | **Live** (logical cap; physical per-connection cap lands with the egress proxy) |
| 9 | Tamper-evident audit trail | Append-only, hash-chained log of every engagement action; `rt audit verify` reports the first break | `orchestrator/rt/audit.py` | **Live** (SQLite tested; Postgres backend untested in CI) |
| 10 | Authenticated operator edge | Gateway authenticates bearer tokens (constant-time), scopes each operator to engagements, injects the authenticated operator into approvals so it can't be forged; TLS available | `gateway/main.go` | **Live** (enable TLS for real use; token store is a static file — no rotation/expiry yet) |

## Defense in depth

The scope guarantee is enforced at **two independent points**, by design:

- **Logical** — the Python orchestrator rejects out-of-scope targets early, and
  the compiled Go policy-gate re-decides every target authoritatively (signature
  + trust + time window + rate). The gate is LLM-free and small on purpose.
- **Physical** — the sandbox runtime pins each tool's egress to the gate's proxy
  so a tool that ignores proxy settings and opens a raw socket is still stopped
  in the kernel. This is the seam that is designed and fail-closed but not yet
  running (see *Current limitations*).

Every enforcement point **fails closed**: an unsigned or untrusted scope, a
malformed window, an unreachable gate, or a runtime that cannot pin egress all
result in *refusal*, never in defaulting open.

## Evidence & non-repudiation

`rt.audit` records `engagement.init`, `finding.add`, `task.create`,
`task.confirm`, `task.dispatch`, `task.blocked`, and `task.conclude` as an
append-only chain where `entry_hash = sha256(prev_hash + canonical(entry))`. Any
edit, deletion, or reorder breaks the chain, and `rt audit verify` reports the
first broken sequence number. No secret is needed to verify — a client or
auditor checks it independently. Crucially, an exploit approval is recorded under
the **authenticated** operator identity (stamped by the gateway, not supplied by
the client), so "who authorized this action" is provable after the fact.

## Current limitations (stated plainly)

- **Physical egress enforcement is not yet live.** Controls #4/#7/#8 are enforced
  logically at the compiled gate, but the kernel-level pin (#5) that stops a
  hostile tool opening a raw socket to an excluded host requires a host with a
  container runtime (gVisor/Firecracker) + nftables. The code seam and the
  fail-closed refusal are in place; the runtime implementation is the next
  milestone (`docs/EGRESS.md`). Until it lands, run RT only against lab targets
  you are prepared to reach under logical enforcement alone.
- **HSM/PKCS#11 signer and the Postgres audit backend are implemented but not
  exercised in CI** (no token / no database in the test environment). The tested
  reference paths are the external-command signer and the SQLite audit backend.
- **Gateway hardening for production:** enable TLS; the token store is a static
  file today (no rotation, expiry, or revocation beyond editing it).

## Verifying these claims

```bash
# Python controls (scope signing, audit chain, gating, window, loop)
cd orchestrator && python3 -m pytest -q          # 41 tests

# Go controls (signature + trust, time window, rate cap, egress seam, gateway auth)
for m in policy-gate gateway sandbox; do (cd $m && go test ./...); done
```

The controls above map to specific, reviewable tests — e.g. tamper detection in
`test_audit.py`, the trust anchor and fail-closed window in
`policy-gate/scope_test.go`, operator-injection-on-approve in
`gateway/main_test.go`, and gated-never-unisolated in `sandbox/runtime_test.go`.
