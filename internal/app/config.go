package app

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/Homiakus/AntigravitiProxi/internal/atomicfile"
	"github.com/Homiakus/AntigravitiProxi/internal/proxy"
)

type Settings struct {
	Listen               string   `json:"listen"`
	ProxyHost            string   `json:"proxy_host"`
	ProxyPort            int      `json:"proxy_port"`
	VPNInterface         string   `json:"vpn_interface"`
	DNSProvider          string   `json:"dns_provider"`
	SingBoxVer           string   `json:"sing_box_version"`
	AutoOpen             bool     `json:"auto_open"`
	TunnelStrictRoute    bool     `json:"tunnel_strict_route"`
	TunnelDomainFallback bool     `json:"tunnel_domain_fallback"`
	TunnelLearnedDomains []string `json:"tunnel_learned_domains,omitempty"`
}

func defaultSettings() Settings {
	return Settings{
		Listen:               "127.0.0.1:48765",
		ProxyHost:            "127.0.0.1",
		ProxyPort:            7890,
		DNSProvider:          "cloudflare",
		SingBoxVer:           proxy.DefaultSingBoxVersion,
		AutoOpen:             true,
		TunnelStrictRoute:    false,
		TunnelDomainFallback: false,
	}
}

func loadSettings(path string) Settings {
	defaults := defaultSettings()
	s := defaults
	b, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	_ = json.Unmarshal(b, &s)
	if s.Listen == "" {
		s.Listen = defaults.Listen
	}
	if s.ProxyHost == "" {
		s.ProxyHost = defaults.ProxyHost
	}
	if s.ProxyPort == 0 {
		s.ProxyPort = defaults.ProxyPort
	}
	if s.DNSProvider == "" {
		s.DNSProvider = defaults.DNSProvider
	}
	// 1.14.0 is the first stable release used by Agent Tunnel because it adds
	// the TUN dns_mode controls required for selective secure-DNS handling.
	if s.SingBoxVer == "" || s.SingBoxVer == "1.13.1" {
		s.SingBoxVer = proxy.DefaultSingBoxVersion
	}
	// Older configs predate this field. JSON bool cannot distinguish omitted
	// from false, so migrate legacy files by inspecting the raw JSON key.
	// Strict process isolation is the secure migration default; users who
	// explicitly enabled the field keep their chosen compatibility mode.
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) == nil {
		if _, ok := raw["tunnel_domain_fallback"]; !ok {
			s.TunnelDomainFallback = false
		}
	}

	// Network-facing settings fail closed. A stale/manual config may never turn
	// the control plane or local mixed proxy into a LAN/public listener.
	if !isLoopbackListen(s.Listen) {
		s.Listen = defaults.Listen
	}
	if !isLoopbackHost(s.ProxyHost) {
		s.ProxyHost = defaults.ProxyHost
	}
	if s.ProxyPort <= 0 || s.ProxyPort > 65535 {
		s.ProxyPort = defaults.ProxyPort
	}
	s.TunnelLearnedDomains = normalizeLearnedDomains(s.TunnelLearnedDomains)
	return s
}

func saveSettings(path string, s Settings) error {
	if err := validateSettingsSecurity(s); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, append(b, '\n'), 0o600)
}

func validateSettingsSecurity(s Settings) error {
	if !isLoopbackListen(s.Listen) {
		return fmt.Errorf("control-plane listen address must be loopback-only, got %q", s.Listen)
	}
	if !isLoopbackHost(s.ProxyHost) {
		return fmt.Errorf("local proxy host must be loopback-only, got %q", s.ProxyHost)
	}
	if s.ProxyPort <= 0 || s.ProxyPort > 65535 {
		return fmt.Errorf("invalid proxy port %d", s.ProxyPort)
	}
	if len(normalizeLearnedDomains(s.TunnelLearnedDomains)) != len(s.TunnelLearnedDomains) {
		return fmt.Errorf("tunnel learned domains contain invalid or duplicate entries")
	}
	return nil
}

func normalizeLearnedDomains(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		host := strings.ToLower(strings.TrimSpace(raw))
		if host == "" || strings.ContainsAny(host, "/:*?[]") || strings.Contains(host, "..") || !strings.Contains(host, ".") || seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	return isLoopbackHost(host)
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
