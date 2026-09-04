package app

import (
	"encoding/json"
	"os"
	"path/filepath"

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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
