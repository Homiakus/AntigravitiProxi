package app

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Homiakus/AntigravitiProxi/internal/atomicfile"
	"github.com/Homiakus/AntigravitiProxi/internal/proxy"
)

type Settings struct {
	Listen               string `json:"listen"`
	ProxyHost            string `json:"proxy_host"`
	ProxyPort            int    `json:"proxy_port"`
	VPNInterface         string `json:"vpn_interface"`
	DNSProvider          string `json:"dns_provider"`
	SingBoxVer           string `json:"sing_box_version"`
	AutoOpen             bool   `json:"auto_open"`
	TunnelStrictRoute    bool   `json:"tunnel_strict_route"`
	TunnelDomainFallback bool   `json:"tunnel_domain_fallback"`
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
		TunnelDomainFallback: true,
	}
}

func loadSettings(path string) Settings {
	s := defaultSettings()
	b, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	_ = json.Unmarshal(b, &s)
	if s.Listen == "" {
		s.Listen = "127.0.0.1:48765"
	}
	if s.ProxyHost == "" {
		s.ProxyHost = "127.0.0.1"
	}
	if s.ProxyPort == 0 {
		s.ProxyPort = 7890
	}
	if s.DNSProvider == "" {
		s.DNSProvider = "cloudflare"
	}
	// 1.14.0 is the first stable release used by Agent Tunnel because it adds
	// the TUN dns_mode controls required for selective secure-DNS handling.
	if s.SingBoxVer == "" || s.SingBoxVer == "1.13.1" {
		s.SingBoxVer = proxy.DefaultSingBoxVersion
	}
	// Older configs predate this field. JSON bool cannot distinguish omitted
	// from false, so migrate legacy files by inspecting the raw JSON key.
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) == nil {
		if _, ok := raw["tunnel_domain_fallback"]; !ok {
			s.TunnelDomainFallback = true
		}
	}
	return s
}

func saveSettings(path string, s Settings) error {
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
	return nil
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
