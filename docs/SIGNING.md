# Signing the Rules of Engagement

RT's scope signature is the liability spine: it attests that the operator
authorized exactly the targets in `scope.json`. The signature is **Ed25519**
(RFC 8032). Verification is asymmetric — the policy-gate and any auditor verify
with the operator's public key and can never forge a scope — and the gate also
requires the signing key to be in its provisioned **trust store** (`-trust`), so
a cryptographically valid signature from an unknown key is still rejected.

The private key sits behind a pluggable **signer** (`rt.signing`). Choose a
backend by how the key is held; the verify path is identical for all of them.

## Backends

| Backend | URI | Key location | Use |
|---|---|---|---|
| Seed file | `seed:operator.key` (or `--key operator.key`) | 32-byte seed on disk | dev / testing only |
| External command | `cmd:/path/to/signer` | wherever your command keeps it | HSM/KMS/agent wrapper (production) |
| PKCS#11 token | `pkcs11:module=...;key=...;token=...;pin=...` | inside the token | hardware HSM (production, air-gap) |

> The seed-file path is convenient but the key is readable — never use it for a
> real engagement. Pick `cmd:` or `pkcs11:` so RT never holds the private key.

## PKCS#11 (YubiHSM2 / Nitrokey / SoftHSM)

Install the backend: `pip install "rt-orchestrator[hsm]"`. Provision an Ed25519
key in the token out of band, e.g.:

```bash
pkcs11-tool --module $PKCS11_MODULE --login --keypairgen \
    --key-type EC:edwards25519 --label operator
```

Then sign and publish the public key into the gate's trust store:

```bash
rt scope sign --operator you@hexalab.my \
    --signer "pkcs11:module=$PKCS11_MODULE;token=rt;key=operator;pin=$PIN" \
    --file scope.json
# the command prints the public key — add it to trust.json for the policy-gate
```

The private key never leaves the token; RT hands it the canonical scope bytes
and gets back a 64-byte signature.

## External command (any HSM / KMS / agent)

For a key behind something without a PKCS#11 module — a cloud KMS that supports
Ed25519 (e.g. Azure Managed HSM), a remote signing service, a smartcard agent —
wrap it in a small command that implements this contract:

* `<cmd> pubkey` → prints the 64-hex-char raw Ed25519 public key
* `<cmd> sign` (message hex on **stdin**) → prints the 128-hex-char signature

```bash
rt scope sign --operator you@hexalab.my --signer "cmd:/usr/local/bin/rt-hsm-sign" --file scope.json
```

RT self-checks every returned signature against the advertised public key before
trusting it, so a wrong key or a buggy wrapper fails loudly at signing time.

> Note: AWS KMS and Google Cloud KMS do **not** offer Ed25519, so they cannot
> back this signer without changing RT's algorithm. Use a PKCS#11 HSM or an
> Ed25519-capable service (Azure Managed HSM) instead.

## The trust store

The policy-gate starts only with a non-empty trust store and a scope whose
signing key it lists:

```bash
# trust.json — operator public keys the appliance accepts
["ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"]
```

```bash
policy-gate -scope scope.json -trust trust.json
```

Rotating an operator key means adding the new public key to `trust.json` and
re-signing the scope; the old key can then be removed.
