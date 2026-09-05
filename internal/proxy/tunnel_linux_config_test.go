//go:build linux

package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxTunnelConfigPinsReservedIPRoute2Namespace(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tunnel.json")
	cfg := Config{
		Root:         root,
		Host:         "127.0.0.1",
		Port:         17891,
		VPNInterface: "vpn0",
		DNSProvider:  "cloudflare",
		SingBoxVer:   DefaultSingBoxVersion,
	}
	if err := writeAgentTunnelConfig(cfg, path, DefaultAgentTunnelOptions()); err != nil {
		t.Fatalf("write Agent Tunnel config: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	inbounds, ok := doc["inbounds"].([]any)
	if !ok {
		t.Fatalf("missing inbounds: %#v", doc["inbounds"])
	}
	var tun map[string]any
	for _, raw := range inbounds {
		m, _ := raw.(map[string]any)
		if m["type"] == "tun" {
			tun = m
			break
		}
	}
	if tun == nil {
		t.Fatal("generated config has no TUN inbound")
	}
	if got := int(tun["iproute2_table_index"].(float64)); got != linuxTunnelRouteTableIndex {
		t.Fatalf("iproute2_table_index=%d want=%d", got, linuxTunnelRouteTableIndex)
	}
	if got := int(tun["iproute2_rule_index"].(float64)); got != linuxTunnelRuleStart {
		t.Fatalf("iproute2_rule_index=%d want=%d", got, linuxTunnelRuleStart)
	}
	if got, _ := tun["auto_redirect"].(bool); got {
		t.Fatal("Linux Agent Tunnel must keep auto_redirect disabled")
	}
}
