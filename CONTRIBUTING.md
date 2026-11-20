# Contributing to RT

Thanks for your interest in RT. This repository is the **Community Edition**
(Apache-2.0). Contributions are welcome under the terms below.

## Ground rules

- RT is tooling for **authorized** security testing. Contributions must not
  weaken RT's safety model — in particular the signed scope, the operator
  confirmation gate for `exploit`/`post`/`destructive` tasks, the policy-gate,
  and the egress proxy. Changes that bypass or disable these will not be
  merged.
- Do not add exploit payloads, target-specific attack code, or any content
  whose primary purpose is to cause harm. RT orchestrates authorized tools; it
  is not a payload repository.
- By submitting a contribution you agree it is licensed under the Apache
  License 2.0 (the Apache-2.0 inbound = outbound convention), and you certify
  you have the right to submit it (Developer Certificate of Origin).

## Development

```bash
make test          # Python (pytest) + Go test suites
make build         # build the Go services and install the orchestrator
make fmt           # gofmt the Go services
```

- The Python core is **stdlib-only by design** (it must run on an air-gapped
  appliance). Please do not add runtime dependencies to
  `orchestrator/pyproject.toml` without discussion — `dev` extras (pytest) are
  fine.
- Go services target the standard library where practical for the same reason.
- Add or update tests with any behavioural change. Safety-critical code (scope,
  gating, egress, audit) must keep its tests green and should gain tests for
  new paths.

## Pull requests

1. Open an issue first for anything non-trivial, so we can agree on the
   approach.
2. Keep PRs focused; describe the change and its safety implications.
3. Ensure `make test` passes and the tree is formatted.

## Reporting security issues

See [`SECURITY.md`](SECURITY.md) — please report privately, not as a public
issue.
