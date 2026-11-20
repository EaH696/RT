package main

import "log"

// Entry point is a scaffold placeholder. The sandbox will expose a gRPC service
// (see /proto/rt.proto) that the orchestrator calls to run tools. For now this
// keeps the module building and documents the wiring.
//
// The runtime seam is real: in production, construct the Runner with a pinned
// (gVisor/Firecracker) ContainerRuntime and the egress-proxy address, so every
// tool runs with its network locked to the policy-gate. See docs/EGRESS.md.
func main() {
	log.Println("rt-sandbox scaffold — wire the gRPC ToolRunner service here (see proto/rt.proto)")
	// Production wiring (once the pinned runtime lands on the host):
	//   r := &Runner{Gate: gate, Adapters: DefaultAdapters(),
	//       Runtime: PinnedRuntime{Kind: "gvisor"}, EgressProxy: "127.0.0.1:8900"}
	// Development only (NOT isolated — egress cannot be pinned):
	r := &Runner{Adapters: DefaultAdapters(), Runtime: LocalRuntime{}, AllowUnisolated: true}
	_ = r
}
