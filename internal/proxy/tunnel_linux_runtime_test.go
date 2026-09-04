//go:build linux

package proxy

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLinuxAgentTunnelRuntimeSmoke is opt-in and is executed by CI inside an
// isolated Linux network namespace. Unlike the schema test, this starts the
// real pinned sing-box, creates the TUN, installs routes/nftables state, checks
// the mixed port, then performs a graceful shutdown and verifies TUN cleanup.
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

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
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
