package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteAgentTunnelConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sing-box.json")
	cfg := Config{
		Root:         dir,
		Host:         "127.0.0.1",
		Port:         7890,
		VPNInterface: "TestVPN",
		DNSProvider:  "cloudflare",
		SingBoxVer:   "1.13.1",
	}
	if err := writeAgentTunnelConfig(cfg, path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	inbounds, ok := doc["inbounds"].([]any)
	if !ok || len(inbounds) != 2 {
		t.Fatalf("inbounds = %#v, want mixed+tun", doc["inbounds"])
	}
	foundTun := false
	for _, raw := range inbounds {
		in, _ := raw.(map[string]any)
		if in["tag"] == agentTunnelTag {
			foundTun = true
			if in["auto_route"] != true {
				t.Fatalf("TUN auto_route not enabled: %#v", in)
			}
			if runtime.GOOS == "linux" && in["auto_redirect"] != true {
				t.Fatalf("Linux Agent Tunnel must enable auto_redirect: %#v", in)
			}
		}
	}
	if !foundTun {
		t.Fatal("agent-tun inbound not found")
	}

	outbounds, _ := doc["outbounds"].([]any)
	foundAgentVPN := false
	for _, raw := range outbounds {
		out, _ := raw.(map[string]any)
		if out["tag"] == "agent-vpn" {
			foundAgentVPN = true
			if out["bind_interface"] != "TestVPN" {
				t.Fatalf("agent-vpn bind_interface = %#v", out["bind_interface"])
			}
		}
	}
	if !foundAgentVPN {
		t.Fatal("agent-vpn outbound not found")
	}

	route, _ := doc["route"].(map[string]any)
	if route["final"] != "system-direct" {
		t.Fatalf("route.final = %#v, want system-direct", route["final"])
	}
	if route["auto_detect_interface"] != true {
		t.Fatalf("route.auto_detect_interface = %#v", route["auto_detect_interface"])
	}

	dns, _ := doc["dns"].(map[string]any)
	if dns["final"] != "system-local" {
		t.Fatalf("dns.final = %#v, want system-local", dns["final"])
	}
}

func TestAgentTunnelConfigAvoidsGlobalNodeRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sing-box.json")
	cfg := Config{Root: dir, Host: "127.0.0.1", Port: 7890, VPNInterface: "VPN", DNSProvider: "google"}
	if err := writeAgentTunnelConfig(cfg, path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !containsAll(text, `"node.exe"`, `"googleapis.com"`, `"system-direct"`, `"agent-vpn"`) {
		t.Fatalf("expected scoped node/Google routing markers in config:\n%s", text)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !stringsContains(s, p) {
			return false
		}
	}
	return true
}

func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
