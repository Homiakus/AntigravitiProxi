package proxy

import (
	"encoding/json"
	"os"
	"os/exec"
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
	if runtime.GOOS == "linux" {
		if tun["strict_route"] != true {
			t.Fatal("Linux Agent Tunnel must use strict_route so local flows enter the TUN before process classification")
		}
		// Deliberate design choice: sing-box 1.14 auto_redirect installs a
		// fallback ip-rule after Linux main/default, which allowed an ordinary
		// host default route to bypass our process policy in the dual-egress
		// runtime test. Keep it disabled until a selective kernel capture design
		// can prove the same isolation invariant.
		if tun["auto_redirect"] != false {
			t.Fatal("Linux Agent Tunnel must keep auto_redirect disabled for authoritative process routing")
		}
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
	processIndex := -1
	sniffIndex := -1
	for i, raw := range rules {
		rule, _ := raw.(map[string]any)
		if _, ok := rule["process_name"]; ok && rule["outbound"] == "vpn-direct" {
			foundProcessRule = true
			if processIndex < 0 {
				processIndex = i
			}
		}
		if rule["action"] == "sniff" && sniffIndex < 0 {
			sniffIndex = i
		}
	}
	if !foundProcessRule {
		t.Fatal("process_name -> vpn-direct rule missing")
	}
	if sniffIndex >= 0 && processIndex >= sniffIndex {
		t.Fatalf("process policy must precede sniff for sing-box pre-match semantics: process=%d sniff=%d", processIndex, sniffIndex)
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

// CI sets AGP_SINGBOX_BIN to the official pinned binary. Keeping this test
// optional makes ordinary `go test ./...` fast and offline-friendly while the
// main branch still validates the generated JSON against sing-box's real
// schema on every push.
func TestAgentTunnelConfigAcceptedByRealSingBox(t *testing.T) {
	bin := os.Getenv("AGP_SINGBOX_BIN")
	if bin == "" {
		t.Skip("AGP_SINGBOX_BIN not set")
	}
	root := t.TempDir()
	path := filepath.Join(root, "tunnel.json")
	cfg := Config{
		Root:         root,
		Host:         "127.0.0.1",
		Port:         17890,
		VPNInterface: "lo",
		DNSProvider:  "cloudflare",
		SingBoxVer:   DefaultSingBoxVersion,
	}
	if err := writeAgentTunnelConfig(cfg, path, DefaultAgentTunnelOptions()); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "check", "-c", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real sing-box rejected Agent Tunnel config: %v\n%s", err, out)
	}
}
