package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
)

// The sandbox service. Exposes ToolRunner.Run over HTTP+JSON (proto/rt.proto)
// and runs an EgressProxy that physically confines tool egress to in-scope
// hosts (decision delegated to the policy-gate). Every run is scope-checked and
// refuses unconfirmed gated tiers.
func main() {
	addr := flag.String("addr", ":8710", "ToolRunner listen address")
	egressAddr := flag.String("egress-addr", ":8720", "egress proxy listen address")
	gateURL := flag.String("gate", os.Getenv("RT_POLICY_GATE_URL"), "policy-gate base URL")
	egressURL := flag.String("egress-url", os.Getenv("RT_EGRESS_URL"), "egress proxy URL given to tools (defaults from -egress-addr)")
	flag.Parse()

	if *gateURL == "" {
		log.Fatalf("sandbox: -gate / RT_POLICY_GATE_URL is required (scope enforcement)")
	}
	gate := newHTTPGate(*gateURL)

	// Egress proxy: the tool's only network route. Decision delegated to the gate.
	proxy := NewEgressProxy(gate, "")
	go func() {
		log.Printf("rt-egress-proxy listening on %s (scope via %s)", *egressAddr, *gateURL)
		log.Fatal(http.ListenAndServe(*egressAddr, proxy))
	}()

	egress := *egressURL
	if egress == "" {
		// *egressAddr may be ":8720" (host omitted) or "host:port"; build a
		// valid URL for either, so a tool's HTTP(S)_PROXY is never malformed.
		hostport := *egressAddr
		if strings.HasPrefix(hostport, ":") {
			hostport = "127.0.0.1" + hostport
		}
		egress = "http://" + hostport
	}

	runner := &Runner{
		Gate:        gate,
		Adapters:    DefaultAdapters(),
		Runtime:     selectRuntime(),
		EgressProxy: egress,
	}
	log.Printf("rt-sandbox listening on %s (egress pinned to %s)", *addr, egress)
	log.Fatal(http.ListenAndServe(*addr, ToolRunnerServer(runner)))
}

// selectRuntime picks the container runtime in production, the local subprocess
// runtime otherwise. Set RT_CONTAINER_SHIM to a gVisor/Firecracker launcher.
func selectRuntime() Runtime {
	if shim := os.Getenv("RT_CONTAINER_SHIM"); shim != "" {
		log.Printf("sandbox: using ContainerRuntime shim %s", shim)
		return ContainerRuntime{RunShim: shim}
	}
	log.Printf("sandbox: WARNING using LocalRuntime (no isolation) — dev only; set RT_CONTAINER_SHIM in production")
	return LocalRuntime{}
}
