//go:build linux

package proxy

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Second)
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

	routeAttestation := m.AttestAgentRoutes(ctx)
	if !routeAttestation.Available {
		t.Fatalf("route attestation unavailable: %s", routeAttestation.Detail)
	}
	if routeAttestation.AgentUnexpected != 0 {
		t.Fatalf("unexpected Agent route evidence without an injected agent flow: %#v", routeAttestation)
	}

	// The sink server returns the source address it observes. The same remote
	// observer is queried once through local-mixed -> vpn-direct and once by an
	// ordinary direct request from this test process. This proves that the
	// selected outbound has a real external consequence rather than merely a
	// correct-looking sing-box config or connection-tracker tag.
	probeURL := os.Getenv("AGP_EGRESS_PROBE_URL")
	if probeURL == "" {
		t.Fatal("AGP_EGRESS_PROBE_URL is required for observability runtime proof")
	}
	expectedVPN := os.Getenv("AGP_EXPECT_VPN_SOURCE")
	expectedSystem := os.Getenv("AGP_EXPECT_SYSTEM_SOURCE")
	attestation := m.attestPublicEgressWithProviders(ctx, []egressProbeProvider{{
		Name: "ci-source-observer",
		URL:  probeURL,
	}})
	if !attestation.Available {
		t.Fatalf("public egress attestation unavailable: %#v", attestation)
	}
	if expectedVPN != "" {
		found := false
		for _, ip := range attestation.VPNObservedIPs {
			if ip == expectedVPN {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("vpn-direct observed addresses %v do not contain expected %s; attestation=%#v", attestation.VPNObservedIPs, expectedVPN, attestation)
		}
	}
	if expectedSystem != "" && attestation.SystemObservedIP != expectedSystem {
		t.Fatalf("system-direct observed %q want %q; attestation=%#v", attestation.SystemObservedIP, expectedSystem, attestation)
	}
	if expectedVPN != "" && expectedSystem != "" && expectedVPN != expectedSystem && attestation.SystemRelation != "different" {
		t.Fatalf("expected distinct vpn/system egress relation, got %q; attestation=%#v", attestation.SystemRelation, attestation)
	}
	t.Logf("external egress attestation: %s", attestation.Detail)

	// Keep one real Antigravity-named process socket open long enough to join
	// sing-box source-endpoint evidence with /proc socket inode ownership. This
	// closes the gap between a path-based routing rule and a concrete live PID.
	probeBin := strings.TrimSpace(os.Getenv("AGP_EGRESS_PROBE_BIN"))
	if probeBin == "" {
		t.Fatal("AGP_EGRESS_PROBE_BIN is required for PID route attestation")
	}
	pidProbe := filepath.Join(root, "antigravity-pid-probe")
	if err := copyFile(probeBin, pidProbe, 0o755); err != nil {
		t.Fatalf("prepare PID probe: %v", err)
	}
	holdURL := strings.TrimRight(probeURL, "/") + "/hold"
	cmd := exec.Command(pidProbe, holdURL)
	cmd.Env = probeEnvironment(os.Environ())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start PID probe: %v", err)
	}
	pid := cmd.Process.Pid
	waited := false
	defer func() {
		if !waited && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	var pidEvidence PIDRouteAttestation
	deadline := time.Now().Add(4 * time.Second)
	for {
		pidEvidence = m.AttestAgentPIDRoutes(ctx, []int{pid})
		if containsPID(pidEvidence.ActiveCandidatePIDs, pid) && containsPID(pidEvidence.VPNDirectPIDs, pid) {
			break
		}
		if len(pidEvidence.UnexpectedPIDs) > 0 {
			t.Fatalf("PID probe selected an unexpected outbound: %#v", pidEvidence)
		}
		if time.Now().After(deadline) {
			conns, _ := m.RuntimeConnections(ctx)
			t.Fatalf("PID/socket route correlation timeout for pid=%d; evidence=%#v connections=%#v stderr=%q", pid, pidEvidence, conns, stderr.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if pidEvidence.AmbiguousConnections != 0 || len(pidEvidence.UnexpectedPIDs) != 0 {
		t.Fatalf("PID route evidence is not exact: %#v", pidEvidence)
	}
	if err := cmd.Wait(); err != nil {
		waited = true
		t.Fatalf("PID probe failed: %v stderr=%q", err, stderr.String())
	}
	waited = true
	if got := strings.TrimSpace(stdout.String()); expectedVPN != "" && got != expectedVPN {
		t.Fatalf("PID-attributed probe external source=%q want vpn=%q; evidence=%#v", got, expectedVPN, pidEvidence)
	}
	t.Logf("PID-level route attestation: pid=%d %s", pid, pidEvidence.Detail)
}

func containsPID(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
