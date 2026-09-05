//go:build linux

package proxy

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestLinuxAgentTunnelCrashRecoveryPreservesUnrelatedRoutingState exercises the
// power-loss/SIGKILL boundary that graceful cleanup cannot cover. It injects an
// unrelated route table/rule after Agent Tunnel is already active, kills the
// managed sing-box without StopAndWait, then creates a fresh Manager and runs
// journal recovery. Recovery must clean the reserved AntigravitiProxi namespace
// while preserving the concurrent unrelated network-manager state.
func TestLinuxAgentTunnelCrashRecoveryPreservesUnrelatedRoutingState(t *testing.T) {
	if os.Getenv("AGP_LINUX_TUN_SMOKE") != "1" {
		t.Skip("set AGP_LINUX_TUN_SMOKE=1 to run privileged Linux TUN recovery test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("Linux TUN recovery test must run as root inside an isolated network namespace")
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
		Port:         17892,
		VPNInterface: vpn,
		DNSProvider:  "cloudflare",
		SingBoxVer:   DefaultSingBoxVersion,
	}
	m := New(cfg, nil)
	if err := copyFile(bin, m.ManagedPath(), 0o755); err != nil {
		t.Fatalf("prepare pinned sing-box: %v", err)
	}
	if err := seedRuntimeFixtureProvenance(m); err != nil {
		t.Fatalf("prepare verified provenance: %v", err)
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer startCancel()
	if err := m.StartAgentTunnel(startCtx); err != nil {
		t.Fatalf("start Agent Tunnel: %v", err)
	}

	// Simulate an unrelated network manager changing routing after the active
	// snapshot. Its namespace is deliberately outside our reserved ownership.
	runIPOrFatal(t, "-4", "route", "add", "blackhole", "198.18.0.0/24", "table", "4242")
	runIPOrFatal(t, "-4", "rule", "add", "priority", "4242", "lookup", "4242")
	defer exec.Command("ip", "-4", "rule", "del", "priority", "4242").Run()
	defer exec.Command("ip", "-4", "route", "flush", "table", "4242").Run()

	pid := m.ManagedPID()
	if pid <= 0 {
		t.Fatal("managed PID missing before crash injection")
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Kill(); err != nil {
		t.Fatalf("SIGKILL managed sing-box: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for m.ManagedRunning() {
		if time.Now().After(deadline) {
			t.Fatal("manager did not observe killed sing-box exit")
		}
		time.Sleep(50 * time.Millisecond)
	}
	status := m.NetworkJournalStatus()
	if !status.Open {
		t.Fatal("crash unexpectedly removed durable network-state journal")
	}

	// New process instance: this is the reboot/relaunch recovery boundary.
	m2 := New(cfg, nil)
	recoverCtx, recoverCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer recoverCancel()
	if err := m2.RecoverStaleNetworkState(recoverCtx); err != nil {
		t.Fatalf("recover stale network state: %v", err)
	}

	if _, err := net.InterfaceByName(agentTunName); err == nil {
		t.Fatalf("%s still exists after crash recovery", agentTunName)
	}
	if status := m2.NetworkJournalStatus(); status.Open {
		t.Fatalf("journal still open after recovery: %#v", status)
	}

	// The concurrent unrelated rule/table must survive byte-for-byte enough to
	// retain both its priority and destination. This is the core R-025 negative
	// invariant: recovery must not treat arbitrary before/after differences as
	// owned merely because they appeared during the tunnel lifetime.
	rules, err := exec.Command("ip", "-o", "-4", "rule", "show").CombinedOutput()
	if err != nil {
		t.Fatalf("read IPv4 rules after recovery: %v: %s", err, strings.TrimSpace(string(rules)))
	}
	if !strings.Contains(string(rules), "4242:") {
		t.Fatalf("unrelated rule priority 4242 was removed by recovery:\n%s", rules)
	}
	routes, err := exec.Command("ip", "-o", "-4", "route", "show", "table", "4242").CombinedOutput()
	if err != nil {
		t.Fatalf("read unrelated route table after recovery: %v: %s", err, strings.TrimSpace(string(routes)))
	}
	if !strings.Contains(string(routes), "198.18.0.0/24") {
		t.Fatalf("unrelated route table 4242 was damaged by recovery:\n%s", routes)
	}

	post, err := capturePlatformNetworkSnapshot(recoverCtx)
	if err != nil {
		t.Fatal(err)
	}
	if err := preflightPlatformNetworkOwnership(post); err != nil {
		t.Fatalf("reserved routing namespace is not clean after recovery: %v", err)
	}
}

func runIPOrFatal(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}
