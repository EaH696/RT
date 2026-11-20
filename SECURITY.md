# Security Policy

RT is offensive-security tooling. We take the security of RT itself, and the
safety of the engagements it runs, seriously.

## Acceptable use

RT must only be run against assets you **own** or have **explicit written
authorization** to test. The signed engagement scope (Rules of Engagement) is
the technical control that enforces this; it is not a substitute for a signed
authorization-to-test agreement with the asset owner. Running RT against
systems without authorization may be illegal.

See [`docs/engagement-scope-template.md`](docs/engagement-scope-template.md)
for the authorization/ROE template.

## Reporting a vulnerability

If you find a security vulnerability in RT, please report it privately.

- **Email:** security@hexalab.tech
- Please do **not** open a public issue for security vulnerabilities.
- Include a description, affected version/commit, and reproduction steps.

We aim to acknowledge reports within 3 business days and to provide a
remediation timeline after triage. We support coordinated disclosure and will
credit reporters who wish to be named.

## Scope of this policy

In scope: the RT orchestrator, policy-gate, sandbox/egress proxy, audit log,
and console in this repository.

Out of scope: vulnerabilities in target systems you are testing (that is RT's
job to find), and issues that require running RT outside its documented,
authorized-use model.

## Supported versions

Security fixes are provided for the latest released minor version. During the
`0.x` series, that is the most recent `0.x` tag.
