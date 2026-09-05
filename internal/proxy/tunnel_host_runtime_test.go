//go:build linux

package proxy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Explicit opt-in: temporarily installs real host routes using an existing
// capability-enabled helper. Always stops the helper, including on failures.
func TestLinuxAgentTunnelHostRuntime(t *testing.T) {
	if os.Getenv("AGP_HOST_TUN_SMOKE") != "1" {
		t.Skip("set AGP_HOST_TUN_SMOKE=1 for live host startup/cleanup")
	}
	bin, vpn := os.Getenv("AGP_SINGBOX_BIN"), os.Getenv("AGP_TEST_VPN_INTERFACE")
	if bin == "" || vpn == "" {
		t.Fatal("AGP_SINGBOX_BIN and AGP_TEST_VPN_INTERFACE required")
	}
	// The fixture hard-links the installed capability-bearing helper so the
	// runtime test does not silently lose xattrs. Keep its temporary root on the
	// same filesystem as the managed binary; /tmp is commonly a separate mount.
	root, err := os.MkdirTemp(filepath.Dir(bin), ".agp-runtime-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	m := New(Config{Root: root, Host: "127.0.0.1", Port: 17891, VPNInterface: vpn, DNSProvider: "cloudflare", SingBoxVer: DefaultSingBoxVersion}, nil)
	if err := os.MkdirAll(filepath.Dir(m.ManagedPath()), 0755); err != nil {
		t.Fatal(err)
	}
	// Retain the installed helper's capabilities; never grant privileges here.
	if err := os.Link(bin, m.ManagedPath()); err != nil {
		t.Fatal(err)
	}
	if err := seedRuntimeFixtureProvenance(m); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := m.StopAndWait(ctx); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := m.StartAgentTunnel(ctx); err != nil {
		t.Fatalf("startup: %v\n%s", err, tunnelDebug(m))
	}
	if !m.TunnelRunning() {
		t.Fatal("tunnel not running after startup")
	}
	if status := m.NetworkJournalStatus(); !status.Open || status.Phase != "active" {
		t.Fatalf("journal: %+v", status)
	}
	t.Log("real host TUN startup, owned listener and active network journal verified")
}
