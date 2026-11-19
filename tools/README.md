# Tool adapters

Every external tool RT can drive is one small **Adapter** (see
`sandbox/adapters.go` for the contract and the `nmap`/`nuclei` examples).

An adapter:
- declares a `Name()` (what the agent asks for),
- turns a normalized `ToolRequest` into `argv`,
- takes the **target only from `req.Target`** — the field the policy-gate has
  authorized. An adapter must never accept a target from free-form args, or
  scope enforcement could be bypassed.
- sanitizes any arg that reaches the command line (see `sanitizePorts`).

Each adapter also declares, by the `risk_tier` of the tasks that use it, whether
it needs operator confirmation. Recon/enum tools run automatically; anything
that changes target state is exploit-tier and gated.

Add a tool: implement `Adapter`, register it in `DefaultAdapters()`, add a test
asserting the target is the final argv element and that args can't smuggle a
shell.
