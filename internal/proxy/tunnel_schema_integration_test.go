package proxy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAgentTunnelSchemaWithPinnedSingBox is opt-in because it downloads the
// official pinned sing-box release. CI enables it in a dedicated job. It does
// not create a TUN device: `sing-box check` only parses and validates config.
func TestAgentTunnelSchemaWithPinnedSingBox(t *testing.T) {
	if os.Getenv("AGP_LIVE_SINGBOX_SCHEMA") != "1" {
		t.Skip("set AGP_LIVE_SINGBOX_SCHEMA=1 to validate against the real pinned sing-box")
	}
	if testing.Short() {
		t.Skip("network-backed schema validation disabled in short mode")
	}

	root := t.TempDir()
	cfg := Config{
		Root:         root,
		Host:         "127.0.0.1",
		Port:         17890,
		VPNInterface: "lo",
		DNSProvider:  "cloudflare",
		SingBoxVer:   DefaultSingBoxVersion,
	}
	m := New(cfg, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	bin, err := m.Install(ctx)
	if err != nil {
		t.Fatalf("install pinned sing-box: %v", err)
	}

	path := filepath.Join(root, "agent-tunnel-check.json")
	if err := writeAgentTunnelConfig(cfg, path, DefaultAgentTunnelOptions()); err != nil {
		t.Fatalf("write Agent Tunnel config: %v", err)
	}

	cmd := exec.CommandContext(ctx, bin, "check", "-c", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box %s rejected Agent Tunnel config: %v\n%s", DefaultSingBoxVersion, err, strings.TrimSpace(string(out)))
	}
}
