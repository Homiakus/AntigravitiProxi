//go:build linux

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
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
// real pinned sing-box, creates the TUN, installs routes state, proves
// process/path-aware dual egress, proves the durable network journal reaches
// active, then performs a graceful shutdown and verifies TUN + journal cleanup.
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
	// The workflow itself downloads the exact pinned official release before
	// entering this isolated namespace. The namespace has deliberately no
	// Internet path, so seed provenance for that already-vetted fixture rather
	// than weakening InstallVerified with a production test bypass.
	if err := seedRuntimeFixtureProvenance(m); err != nil {
		t.Fatalf("prepare verified provenance: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := m.StartAgentTunnel(ctx); err != nil {
		t.Fatalf("start Agent Tunnel: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		_, tunErr := net.InterfaceByName(agentTunName)
		owned, _ := m.ManagedListenerOwned()
		if tunErr == nil && owned && m.TunnelRunning() {
			break
		}
		if !m.ManagedRunning() {
			t.Fatalf("sing-box exited during startup:\n%s", tunnelDebug(m))
		}
		if time.Now().After(deadline) {
			t.Fatalf("TUN/owned-listener health timeout:\n%s", tunnelDebug(m))
		}
		time.Sleep(100 * time.Millisecond)
	}

	j, err := m.loadTunnelJournal()
	if err != nil {
		t.Fatalf("load active network journal: %v", err)
	}
	if j == nil || j.Phase != "active" || j.PID != m.ManagedPID() || j.Active == nil {
		t.Fatalf("durable network journal did not reach active with managed PID: %#v", j)
	}
	if j.Before.Platform != "linux" || j.Active.Platform != "linux" {
		t.Fatalf("unexpected journal platform evidence: before=%q active=%q", j.Before.Platform, j.Active.Platform)
	}
	if status := m.NetworkJournalStatus(); !status.Open || status.Phase != "active" {
		t.Fatalf("health-facing journal status is not active/open: %#v", status)
	}

	// The CI topology exposes one destination through two independent L3
	// uplinks. The destination reports the source IP it observed. This proves
	// the central isolation invariant at runtime, rather than only checking JSON:
	//   Antigravity/language_server/bundled helper -> vpn-direct -> vpn0
	//   unrelated process                         -> system-direct -> sys0
	if probeURL := os.Getenv("AGP_EGRESS_PROBE_URL"); probeURL != "" {
		vpnSource := strings.TrimSpace(os.Getenv("AGP_EXPECT_VPN_SOURCE"))
		systemSource := strings.TrimSpace(os.Getenv("AGP_EXPECT_SYSTEM_SOURCE"))
		probeBin := strings.TrimSpace(os.Getenv("AGP_EGRESS_PROBE_BIN"))
		if vpnSource == "" || systemSource == "" {
			t.Fatal("AGP_EXPECT_VPN_SOURCE and AGP_EXPECT_SYSTEM_SOURCE are required with AGP_EGRESS_PROBE_URL")
		}
		if probeBin == "" {
			t.Fatal("AGP_EGRESS_PROBE_BIN is required with AGP_EGRESS_PROBE_URL")
		}
		if st, err := os.Stat(probeBin); err != nil || st.IsDir() {
			t.Fatalf("invalid AGP_EGRESS_PROBE_BIN %q: %v", probeBin, err)
		}

		probeRoot := filepath.Join(root, "egress-probes")
		if err := os.MkdirAll(filepath.Join(probeRoot, "antigravity-bundle"), 0o755); err != nil {
			t.Fatal(err)
		}

		vpnProbes := []struct {
			name string
			path string
		}{
			{name: "antigravity process_name", path: filepath.Join(probeRoot, "antigravity")},
			{name: "language_server process_name", path: filepath.Join(probeRoot, "language_server")},
			{name: "bundled node process_path_regex", path: filepath.Join(probeRoot, "antigravity-bundle", "node")},
		}

		for _, p := range vpnProbes {
			if err := copyFile(probeBin, p.path, 0o755); err != nil {
				t.Fatalf("prepare %s probe: %v", p.name, err)
			}
			got, meta, probeErr := runSourceProbe(p.path, probeURL)
			if probeErr != nil {
				t.Fatalf("%s failed: %v\nprobe: %s\n%s", p.name, probeErr, meta, tunnelDebug(m))
			}
			if got != vpnSource {
				t.Fatalf("%s escaped selected VPN: source=%q want=%q; probe=%s\n%s", p.name, got, vpnSource, meta, tunnelDebug(m))
			}
			t.Logf("%s -> selected VPN source %s (%s)", p.name, got, meta)
		}

		got, meta, probeErr := runSourceProbe(probeBin, probeURL)
		if probeErr != nil {
			t.Fatalf("ordinary process probe failed: %v\nprobe: %s\n%s", probeErr, meta, tunnelDebug(m))
		}
		if got != systemSource {
			t.Fatalf("unrelated process was captured by Agent Tunnel: source=%q want system=%q; probe=%s\n%s", got, systemSource, meta, tunnelDebug(m))
		}
		t.Logf("ordinary process -> system-direct source %s (%s)", got, meta)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := m.StopAndWait(stopCtx); err != nil {
		t.Fatalf("graceful stop: %v; %s", err, tunnelDebug(m))
	}
	if m.ManagedRunning() || m.TunnelRunning() {
		t.Fatal("manager still reports running after graceful stop")
	}

	cleanupDeadline := time.Now().Add(3 * time.Second)
	for {
		_, err := net.InterfaceByName(agentTunName)
		if err != nil {
			break
		}
		if time.Now().After(cleanupDeadline) {
			t.Fatalf("TUN interface still exists after shutdown; config=%s", filepath.Base(m.TunnelConfigPath()))
		}
		time.Sleep(100 * time.Millisecond)
	}

	if _, err := os.Stat(m.networkJournalPath()); !os.IsNotExist(err) {
		t.Fatalf("open network journal remains after graceful recovery: err=%v", err)
	}
	cleanRaw, err := os.ReadFile(m.lastCleanNetworkJournalPath())
	if err != nil {
		t.Fatalf("last-clean network evidence missing: %v", err)
	}
	var clean TunnelStateJournal
	if err := json.Unmarshal(cleanRaw, &clean); err != nil {
		t.Fatalf("decode last-clean network evidence: %v", err)
	}
	if clean.Phase != "clean" || clean.OperationID == "" || clean.PID != 0 {
		t.Fatalf("last-clean evidence is incomplete: %#v", clean)
	}
	if status := m.NetworkJournalStatus(); status.Open {
		t.Fatalf("health still reports open network journal after cleanup: %#v", status)
	}
}

func seedRuntimeFixtureProvenance(m *Manager) error {
	hash, err := sha256File(m.ManagedPath())
	if err != nil {
		return err
	}
	cfg := m.Config()
	p := managedProvenance{
		Version:       cfg.SingBoxVer,
		Asset:         assetNameFor("linux", "amd64", cfg.SingBoxVer),
		ReleaseDigest: "sha256:ci-verified-fixture",
		BinarySHA256:  hash,
		VerifiedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.provenancePath()), 0o755); err != nil {
		return err
	}
	return os.WriteFile(m.provenancePath(), append(b, '\n'), 0o600)
}

func runSourceProbe(binary, target string) (source, meta string, err error) {
	cmd := exec.Command(binary, target)
	cmd.Env = probeEnvironment(os.Environ())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if runErr := cmd.Run(); runErr != nil {
		return "", strings.TrimSpace(stderr.String()), fmt.Errorf("%w: %s", runErr, strings.TrimSpace(stdout.String()))
	}
	return strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), nil
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

func tunnelDebug(m *Manager) string {
	return "sing-box stdout:\n" + tailTestFile(m.LogPath()) + "\nsing-box stderr:\n" + tailTestFile(m.ErrPath())
}

func tailTestFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > 80 {
		lines = lines[len(lines)-80:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
