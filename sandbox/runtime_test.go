package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestLocalRuntimeRuns(t *testing.T) {
	res, err := LocalRuntime{}.Exec(context.Background(), ContainerSpec{
		Argv: []string{"printf", "hi"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "hi" || res.ExitCode != 0 {
		t.Fatalf("got stdout=%q exit=%d", res.Stdout, res.ExitCode)
	}
}

func TestLocalRuntimePinsEgressEnv(t *testing.T) {
	res, err := LocalRuntime{}.Exec(context.Background(), ContainerSpec{
		Argv:        []string{"sh", "-c", "echo $HTTPS_PROXY"},
		EgressProxy: "http://127.0.0.1:8720",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(res.Stdout) != "http://127.0.0.1:8720" {
		t.Fatalf("tool env must route egress through the proxy, got %q", res.Stdout)
	}
}

func TestLocalRuntimeTimeout(t *testing.T) {
	_, err := LocalRuntime{}.Exec(context.Background(), ContainerSpec{
		Argv:    []string{"sleep", "3"},
		Timeout: 50 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestContainerRuntimeStubErrors(t *testing.T) {
	_, err := ContainerRuntime{}.Exec(context.Background(), ContainerSpec{Argv: []string{"x"}})
	if err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("container runtime stub should report unavailable, got %v", err)
	}
}
