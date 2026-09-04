package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAgentTunnelConfigIsProcessAwareAndNonGlobal(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tunnel.json")
	cfg := Config{
		Root:         root,
		Host:         "127.0.0.1",
		Port:         7890,
		VPNInterface: "TEST-VPN",
		DNSProvider:  "cloudflare",
		SingBoxVer:   DefaultSingBoxVersion,
	}
	if err := writeAgentTunnelConfig(cfg, path, DefaultAgentTunnelOptions()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}

	if DefaultSingBoxVersion != "1.14.0" {
		t.Fatalf("Agent Tunnel requires pinned stable 1.14.0, got %q", DefaultSingBoxVersion)
	}

	inbounds, ok := doc["inbounds"].([]any)
	if !ok || len(inbounds) != 2 {
		t.Fatalf("expected mixed + tun inbounds, got %#v", doc["inbounds"])
	}
	var tun map[string]any
	for _, raw := range inbounds {
		in, _ := raw.(map[string]any)
		if in["type"] == "tun" {
			tun = in
		}
	}
	if tun == nil {
		t.Fatal("TUN inbound missing")
	}
	if tun["dns_mode"] != "hijack" || tun["auto_route"] != true {
		t.Fatalf("unexpected TUN DNS/route config: %#v", tun)
	}
	if runtime.GOOS == "linux" && tun["auto_redirect"] != true {
		t.Fatal("Linux Agent Tunnel must enable auto_redirect")
	}

	outbounds, ok := doc["outbounds"].([]any)
	if !ok || len(outbounds) < 2 {
		t.Fatalf("expected vpn-direct + system-direct: %#v", doc["outbounds"])
	}
	foundVPN := false
	foundSystem := false
	for _, raw := range outbounds {
		out, _ := raw.(map[string]any)
		switch out["tag"] {
		case "vpn-direct":
			foundVPN = out["bind_interface"] == "TEST-VPN"
		case "system-direct":
			_, hasBind := out["bind_interface"]
			foundSystem = !hasBind
		}
	}
	if !foundVPN || !foundSystem {
		t.Fatalf("outbound isolation invalid: vpn=%v system=%v", foundVPN, foundSystem)
	}

	route, ok := doc["route"].(map[string]any)
	if !ok {
		t.Fatal("route object missing")
	}
	if route["final"] != "system-direct" || route["auto_detect_interface"] != true {
		t.Fatalf("unrelated apps must retain system-direct route: %#v", route)
	}
	rules, _ := route["rules"].([]any)
	foundProcessRule := false
	for _, raw := range rules {
		rule, _ := raw.(map[string]any)
		if _, ok := rule["process_name"]; ok && rule["outbound"] == "vpn-direct" {
			foundProcessRule = true
		}
	}
	if !foundProcessRule {
		t.Fatal("process_name -> vpn-direct rule missing")
	}

	dns, ok := doc["dns"].(map[string]any)
	if !ok || dns["final"] != "local-dns" {
		t.Fatalf("unrelated DNS must retain local resolver: %#v", doc["dns"])
	}
}

func TestAgentTunnelRequiresExplicitVPNInterface(t *testing.T) {
	cfg := Config{Root: t.TempDir(), Host: "127.0.0.1", Port: 7890}
	err := writeAgentTunnelConfig(cfg, filepath.Join(cfg.Root, "tunnel.json"), DefaultAgentTunnelOptions())
	if err == nil {
		t.Fatal("expected error without VPN interface")
	}
}

func TestAgentTunnelCanDisableDomainFallback(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tunnel.json")
	cfg := Config{Root: root, Host: "127.0.0.1", Port: 7890, VPNInterface: "VPN"}
	opts := DefaultAgentTunnelOptions()
	opts.DomainFallback = false
	if err := writeAgentTunnelConfig(cfg, path, opts); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	route := doc["route"].(map[string]any)
	rules := route["rules"].([]any)
	for _, raw := range rules {
		rule := raw.(map[string]any)
		if _, ok := rule["domain_suffix"]; ok {
			t.Fatalf("domain fallback rule unexpectedly present: %#v", rule)
		}
	}
}
