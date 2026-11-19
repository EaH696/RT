package main

import "log"

// Entry point is a scaffold placeholder. The sandbox will expose a gRPC service
// (see /proto/rt.proto) that the orchestrator calls to run tools. For now this
// keeps the module building and documents the wiring.
func main() {
	log.Println("rt-sandbox scaffold — wire the gRPC ToolRunner service here (see proto/rt.proto)")
	_ = Runner{Adapters: map[string]Adapter{}}
}
