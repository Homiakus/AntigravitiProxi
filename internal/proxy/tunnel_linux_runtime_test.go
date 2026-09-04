//go:build linux

package proxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLinuxAgentTunnelRuntimeSmoke is opt-in and is executed by CI inside an
// isolated Linux network namespace. Unlike the schema test, this starts the
// real pinned sing-box, creates the TUN, installs routes/nftables state, proves
// process/path-aware dual egress, then performs a graceful shutdown and
// verifies TUN cleanup.
func TestLinuxAgentTunnelRuntimeSmoke(t *testing.T) {
	if os.Getenv("AGP_LINUX_TUN_SMOKE") != "1" {
		t.Skip("set AGP_LINUX_TUN_SMOKE=1 to run privileged Linux TUN smoke test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("Linux TUN smoke test must run as root inside an isolated network namespace")
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
	cfg := Config{
		Root:         root,
		Host:         "127.0.0.1",
		Port:         17891,
		VPNInterface: vpn,
		DNSProvider:  "cloudflare",
		SingBoxVer:   DefaultSingBoxVersion,
	}
	m := New(cfg, nil)
	if err := copyFile(bin, m.ManagedPath(), 0o755); err != nil {
		t.Fatalf("prepare pinned sing-box: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := m.StartAgentTunnel(ctx); err != nil {
		t.Fatalf("start Agent Tunnel: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		_, tunErr := net.InterfaceByName("antigravity-tun")
		if tunErr == nil && m.Running() && m.TunnelRunning() {
			break
		}
		if !m.ManagedRunning() {
			b, _ := os.ReadFile(m.ErrPath())
			t.Fatalf("sing-box exited during startup:\n%s", strings.TrimSpace(string(b)))
		}
		if time.Now().After(deadline) {
			b, _ := os.ReadFile(m.ErrPath())
			t.Fatalf("TUN/mixed-port health timeout; stderr:\n%s", strings.TrimSpace(string(b)))
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The CI topology exposes one destination through two interfaces. The
	// destination reports the source IP it observed. This proves the central
	// isolation invariant at runtime, rather than only checking generated JSON:
	//   Antigravity/language_server/bundled helper -> vpn-direct -> vpn0
	//   unrelated process                         -> system-direct -> sys0
	if probeURL := os.Getenv("AGP_EGRESS_PROBE_URL"); probeURL != "" {
		vpnSource := strings.TrimSpace(os.Getenv("AGP_EXPECT_VPN_SOURCE"))
		systemSource := strings.TrimSpace(os.Getenv("AGP_EXPECT_SYSTEM_SOURCE"))
		if vpnSource == "" || systemSource == "" {
			t.Fatal("AGP_EXPECT_VPN_SOURCE and AGP_EXPECT_SYSTEM_SOURCE are required with AGP_EGRESS_PROBE_URL")
		}

		curl, err := exec.LookPath("curl")
		if err != nil {
			t.Fatalf("curl is required for runtime egress probes: %v", err)
		}

		probeRoot := filepath.Join(root, "egress-probes")
		if err = os.MkdirAll(filepath.Join(probeRoot, "antigravity-bundle"), 0o755); err != nil {
			t.Fatal(err)
		}

		// Two process_name probes cover the IDE and language server. The node
		// helper deliberately has a generic process name; only its installation
		// path contains "antigravity", exercising process_path_regex.
		vpnProbes := []struct {
			name string
			path string
		}{
			{name: "antigravity process_name", path: filepath.Join(probeRoot, "antigravity")},
			{name: "language_server process_name", path: filepath.Join(probeRoot, "language_server")},
			{name: "bundled node process_path_regex", path: filepath.Join(probeRoot, "antigravity-bundle", "node")},
		}

		for _, p := range vpnProbes {
			if err = copyFile(curl, p.path, 0o755); err != nil {
				t.Fatalf("prepare %s probe: %v", p.name, err)
			}
			got, probeErr := runSourceProbe(p.path, probeURL)
			if probeErr != nil {
				t.Fatalf("%s failed: %v\nsing-box stderr:\n%s", p.name, probeErr, tailTestFile(m.ErrPath()))
			}
			if got != vpnSource {
				t.Fatalf("%s escaped selected VPN: source=%q want=%q", p.name, got, vpnSource)
			}
			t.Logf("%s -> selected VPN source %s", p.name, got)
		}

		got, probeErr := runSourceProbe(curl, probeURL)
		if probeErr != nil {
			t.Fatalf("ordinary process probe failed: %v\nsing-box stderr:\n%s", probeErr, tailTestFile(m.ErrPath()))
		}
		if got != systemSource {
			t.Fatalf("unrelated process was captured by Agent Tunnel: source=%q want system=%q", got, systemSource)
		}
		t.Logf("ordinary process -> system-direct source %s", got)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := m.StopAndWait(stopCtx); err != nil {
		b, _ := os.ReadFile(m.ErrPath())
		t.Fatalf("graceful stop: %v; stderr:\n%s", err, strings.TrimSpace(string(b)))
	}
	if m.ManagedRunning() || m.TunnelRunning() {
		t.Fatal("manager still reports running after graceful stop")
	}

	cleanupDeadline := time.Now().Add(3 * time.Second)
	for {
		_, err := net.InterfaceByName("antigravity-tun")
		if err != nil {
			break
		}
		if time.Now().After(cleanupDeadline) {
			t.Fatalf("TUN interface still exists after shutdown; config=%s", filepath.Base(m.TunnelConfigPath()))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func runSourceProbe(binary, target string) (string, error) {
	cmd := exec.Command(binary,
		"--silent",
		"--show-error",
		"--fail",
		"--connect-timeout", "3",
		"--max-time", "6",
		"--noproxy", "*",
		target,
	)
	cmd.Env = probeEnvironment(os.Environ())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func probeEnvironment(base []string) []string {
	blocked := map[string]bool{
		"HTTP_PROXY": true,
		"HTTPS_PROXY": true,
		"ALL_PROXY": true,
		"NO_PROXY": true,
	}
	out := make([]string, 0, len(base)+2)
	for _, item := range base {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) == 2 && blocked[strings.ToUpper(parts[0])] {
			continue
		}
		out = append(out, item)
	}
	return append(out, "NO_PROXY=*", "no_proxy=*")
}

func tailTestFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > 60 {
		lines = lines[len(lines)-60:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
