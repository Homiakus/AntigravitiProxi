//go:build linux

package proxy

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLinuxAgentTunnelObservabilityRuntime(t *testing.T) {
	if os.Getenv("AGP_LINUX_TUN_SMOKE") != "1" {
		t.Skip("set AGP_LINUX_TUN_SMOKE=1 to run privileged Linux observability test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("Linux observability test must run as root inside an isolated network namespace")
	}
	bin := os.Getenv("AGP_SINGBOX_BIN")
	if bin == "" {
		t.Fatal("AGP_SINGBOX_BIN is required")
	}
	vpn := os.Getenv("AGP_TEST_VPN_INTERFACE")
	if vpn == "" {
		vpn = "vpn0"
	}

	root := t.TempDir()
	m := New(Config{
		Root:         root,
		Host:         "127.0.0.1",
		Port:         17893,
		VPNInterface: vpn,
		DNSProvider:  "cloudflare",
		SingBoxVer:   DefaultSingBoxVersion,
	}, nil)
	if err := copyFile(bin, m.ManagedPath(), 0o755); err != nil {
		t.Fatalf("prepare pinned sing-box: %v", err)
	}
	if err := seedRuntimeFixtureProvenance(m); err != nil {
		t.Fatalf("prepare verified provenance: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := m.StartAgentTunnel(ctx); err != nil {
		t.Fatalf("start Agent Tunnel: %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		if err := m.StopAndWait(stopCtx); err != nil {
			t.Errorf("stop Agent Tunnel: %v", err)
		}
	}()

	// The API is a separate authenticated loopback service, not the mixed proxy.
	// Successfully listing connections proves the pinned 1.14 daemon accepted
	// the generated API service, the bearer secret matches and the CLI can query
	// the live connection tracker without importing unstable protobuf packages.
	connections, err := m.RuntimeConnections(ctx)
	if err != nil {
		t.Fatalf("runtime connection snapshot: %v", err)
	}
	t.Logf("authenticated sing-box API returned %d live connections", len(connections))

	attestation := m.AttestAgentRoutes(ctx)
	if !attestation.Available {
		t.Fatalf("route attestation unavailable: %s", attestation.Detail)
	}
	if attestation.AgentUnexpected != 0 {
		t.Fatalf("unexpected Agent route evidence without an injected agent flow: %#v", attestation)
	}
}
