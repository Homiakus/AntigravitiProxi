//go:build linux

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestLinuxDomainFallbackIsolationRuntime proves the exact isolation trade-off
// of DomainFallback with the real pinned sing-box in the deterministic dual-
// egress namespace. The same unrelated process and same destination are used in
// both phases; only the routing policy changes.
func TestLinuxDomainFallbackIsolationRuntime(t *testing.T) {
	if os.Getenv("AGP_LINUX_TUN_SMOKE") != "1" {
		t.Skip("set AGP_LINUX_TUN_SMOKE=1 to run privileged Linux TUN policy test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("Linux domain-fallback runtime test must run as root inside an isolated network namespace")
	}
	bin := strings.TrimSpace(os.Getenv("AGP_SINGBOX_BIN"))
	probeBin := strings.TrimSpace(os.Getenv("AGP_EGRESS_PROBE_BIN"))
	probeURL := strings.TrimSpace(os.Getenv("AGP_EGRESS_PROBE_URL"))
	vpnSource := strings.TrimSpace(os.Getenv("AGP_EXPECT_VPN_SOURCE"))
	systemSource := strings.TrimSpace(os.Getenv("AGP_EXPECT_SYSTEM_SOURCE"))
	vpn := strings.TrimSpace(os.Getenv("AGP_TEST_VPN_INTERFACE"))
	if vpn == "" {
		vpn = "vpn0"
	}
	if bin == "" || probeBin == "" || probeURL == "" || vpnSource == "" || systemSource == "" {
		t.Fatal("AGP_SINGBOX_BIN, AGP_EGRESS_PROBE_BIN, AGP_EGRESS_PROBE_URL and expected source variables are required")
	}

	root := t.TempDir()
	m := New(Config{
		Root:         root,
		Host:         "127.0.0.1",
		Port:         17894,
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

	// The URL is an IP address in the controlled sink namespace. Overriding the
	// HTTP Host lets sing-box's sniff step observe a Google target domain without
	// any external DNS dependency. The client binary itself remains unrelated to
	// Antigravity, so process/path rules cannot explain the selected outbound.
	const targetHost = "cloudcode-pa.googleapis.com"

	startAndProbe := func(fallback bool, want string) {
		t.Helper()
		opts := DefaultAgentTunnelOptions()
		opts.DomainFallback = fallback
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := m.StartAgentTunnel(ctx, opts); err != nil {
			t.Fatalf("start Agent Tunnel fallback=%v: %v\n%s", fallback, err, tunnelDebug(m))
		}
		waitRuntimeTunnelReady(t, m)

		got, meta, err := runSourceProbeWithHost(probeBin, probeURL, targetHost)
		if err != nil {
			t.Fatalf("fallback=%v unrelated domain probe failed: %v\nprobe=%s\n%s", fallback, err, meta, tunnelDebug(m))
		}
		if got != want {
			t.Fatalf("fallback=%v unrelated Google-domain source=%q want=%q; probe=%s\n%s", fallback, got, want, meta, tunnelDebug(m))
		}
		t.Logf("domain_fallback=%v unrelated process host=%s -> source %s (%s)", fallback, targetHost, got, meta)

		stopCtx, stopCancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer stopCancel()
		if err := m.StopAndWait(stopCtx); err != nil {
			t.Fatalf("stop Agent Tunnel fallback=%v: %v\n%s", fallback, err, tunnelDebug(m))
		}
	}

	// Relaxed policy intentionally captures the target domain even though the
	// process itself is unrelated. This is compatibility behavior, not strict
	// process isolation, and must therefore remain visible in UI/assurance.
	startAndProbe(true, vpnSource)

	// With fallback disabled, the exact same unrelated process/Host pair must
	// return to the system-direct path.
	startAndProbe(false, systemSource)
}

func waitRuntimeTunnelReady(t *testing.T, m *Manager) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, tunErr := net.InterfaceByName(agentTunName)
		owned, _ := m.ManagedListenerOwned()
		if tunErr == nil && owned && m.TunnelRunning() {
			return
		}
		if !m.ManagedRunning() {
			t.Fatalf("sing-box exited during runtime policy startup:\n%s", tunnelDebug(m))
		}
		if time.Now().After(deadline) {
			t.Fatalf("runtime policy TUN/listener readiness timeout:\n%s", tunnelDebug(m))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func runSourceProbeWithHost(binary, target, host string) (source, meta string, err error) {
	cmd := exec.Command(binary, target, host)
	cmd.Env = probeEnvironment(os.Environ())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if runErr := cmd.Run(); runErr != nil {
		return "", strings.TrimSpace(stderr.String()), fmt.Errorf("%w: %s", runErr, strings.TrimSpace(stdout.String()))
	}
	return strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), nil
}
