package main

import (
	"flag"
	"log"
	"net/http"
	"os"
)

// The sandbox service. Exposes ToolRunner.Run over HTTP+JSON (proto/rt.proto);
// swap to gRPC by generating stubs from the proto and serving them instead.
// Every run is scope-checked against the policy-gate and refuses gated tiers
// that are not operator-confirmed (see Runner.Run).
func main() {
	addr := flag.String("addr", ":8710", "listen address")
	gateURL := flag.String("gate", os.Getenv("RT_POLICY_GATE_URL"), "policy-gate base URL")
	flag.Parse()

	runner := &Runner{Adapters: DefaultAdapters()}
	if *gateURL != "" {
		runner.Gate = newHTTPGate(*gateURL)
		log.Printf("sandbox: scope checks via policy-gate at %s", *gateURL)
	} else {
		log.Printf("sandbox: WARNING no -gate/RT_POLICY_GATE_URL set — scope checks disabled (dev only)")
	}
	log.Printf("rt-sandbox listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, ToolRunnerServer(runner)))
}
