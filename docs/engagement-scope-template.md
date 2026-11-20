# Engagement Scope & Rules of Engagement (RoE) — Template

**HexaLab Technologies — Penetration Testing Authorization**

> This document is the legal basis for an engagement. Nothing is tested until an
> authorized representative of the **Client** has signed Section 10, and the
> machine-readable `scope.json` (Section 8) has been signed by the HexaLab
> operator with `rt scope sign`. The `scope.json` RT enforces must never be
> broader than what is authorized here. If the two disagree, testing stops.

Fill every field. Delete the parenthetical guidance before signing.

---

## 1. Parties

| | |
|---|---|
| **Client (legal entity)** | _(full registered name)_ |
| **Client authorized signatory** | _(name, title — must have authority to grant access to the assets below)_ |
| **Testing provider** | HexaLab Technologies |
| **Lead tester / operator** | _(name, email@hexalab.my)_ |
| **Engagement ID** | _(e.g. ACME-2026-01 — reused as `engagement_id` in `scope.json`)_ |

## 2. Authorization statement

The Client authorizes HexaLab Technologies to perform security testing
(penetration testing / vulnerability assessment) against **only** the assets
listed in Section 4, within the window in Section 3, subject to the rules in
Sections 5–7. The Client confirms it owns or has lawful authority over those
assets and the authority to grant this permission. This authorization may be
withdrawn in writing at any time (see Section 9).

## 3. Test window

| | |
|---|---|
| **Start** | _(date/time, ISO8601, with timezone — e.g. 2026-12-01T00:00:00+08:00)_ |
| **End** | _(date/time)_ |
| **Permitted hours** | _(e.g. 00:00–06:00 MYT, or "any time")_ |
| **Change-freeze / blackout dates** | _(dates when testing must not run)_ |

## 4. In-scope targets

List exactly what may be tested. Be specific; anything not listed is out of scope.

| Type | Value | Owner-confirmed? | Notes |
|---|---|---|---|
| Domain | _(app.client.com)_ | ☐ | _(prod / staging)_ |
| Domain (wildcard) | _(*.client.com)_ | ☐ | |
| IP / CIDR | _(203.0.113.0/24)_ | ☐ | |
| Web application | _(URL + which flows)_ | ☐ | |
| API | _(base URL / spec)_ | ☐ | |
| Cloud account | _(provider + account ID)_ | ☐ | _(see Section 6)_ |

## 5. Out-of-scope / exclusions

Assets and techniques that must **not** be touched, even if reachable.

- **Excluded assets:** _(IPs/CIDRs, domains, specific hosts — e.g. production
  database 203.0.113.9, third-party-hosted pages, shared infrastructure)_
- **Excluded techniques:** _(e.g. denial-of-service / load testing, social
  engineering, physical access, destructive actions, testing of third-party
  services the Client does not control)_

## 6. Third-party / hosting authorization

If in-scope assets are hosted by a cloud or CDN provider (AWS, GCP, Azure,
Cloudflare, etc.), confirm the provider's testing policy has been met and any
required notification filed. List provider + reference here:

- _(provider, account, notification/reference, date)_

## 7. Rules & constraints

- **Rate limiting:** cap at _(e.g. 50)_ requests/sec per host to avoid service
  impact (maps to `max_rps`).
- **Exploitation:** permitted only to prove a finding; the operator must confirm
  each exploit-tier action (RT enforces this via the confirmation gate).
- **Destructive actions:** _(prohibited unless explicitly listed here)_.
- **Sensitive data (PII/credentials):** capture the minimum needed as evidence;
  do not exfiltrate bulk data. Handle per PDPA 2010. Evidence encrypted at rest,
  retained _(N)_ days, then destroyed; destruction confirmed to Client.
- **Stop conditions:** testing pauses immediately on _(e.g. signs of outage,
  discovery of criticality X, Client request)_ and the operator contacts the
  Client.

## 8. Machine-readable scope (`scope.json`)

RT enforces this file. It must be a faithful subset of Sections 4–5 and 7.
Create and sign it:

```bash
rt scope new --engagement ACME-2026-01 \
    --allow 203.0.113.0/24 --allow app.client.com \
    --exclude 203.0.113.9/32 \
    --file scope.json
# review scope.json against this document, then:
rt scope sign --operator <you@hexalab.my> --file scope.json
rt --store .rt init --engagement ACME-2026-01 \
    --objective "<objective>" --scope scope.json
```

Field mapping (see `docs/scope.example.json`):

| `scope.json` field | From this document |
|---|---|
| `engagement_id` | Section 1 |
| `allowed_cidrs` / `allowed_domains` | Section 4 (IP ranges / domains) |
| `excluded_cidrs` / `excluded_domains` | Section 5 (excluded assets) |
| `window_start` / `window_end` | Section 3 |
| `max_rps` | Section 7 (rate limit) |
| `signed_by` / `signature` | set by `rt scope sign` (operator attestation) |

The signature is the operator's attestation that `scope.json` matches this
signed authorization. The policy-gate refuses to start on an unsigned or
tampered scope, and refuses every target outside it.

## 9. Emergency contacts & withdrawal

| Role | Name | Contact (24/7) |
|---|---|---|
| Client incident contact | | |
| Client authorized signatory | | |
| HexaLab lead operator | | |

Authorization may be withdrawn by written notice to the HexaLab lead operator;
testing stops on receipt.

## 10. Signatures

By signing, the Client authorized signatory confirms authority to grant this
permission and that the in-scope assets are owned or lawfully controlled by the
Client.

| | Client | HexaLab Technologies |
|---|---|---|
| Name | | |
| Title | | |
| Signature | | |
| Date | | |

---

_Governing law: Malaysia (incl. Computer Crimes Act 1997; Personal Data
Protection Act 2010). This template is operational guidance, not legal advice —
have your final contract reviewed by counsel._
