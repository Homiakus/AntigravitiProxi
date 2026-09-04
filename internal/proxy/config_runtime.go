package proxy

import (
	"fmt"
	"net"
	"strings"
)

// UpdateStoppedConfig changes data-plane configuration only while the managed
// process is stopped. Mutating Manager.cfg while sing-box is already running
// would make status/config diverge from the actual loaded sing-box config.
func (m *Manager) UpdateStoppedConfig(host string, port int, vpnInterface, dnsProvider, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil && m.cmd.Process != nil {
		return fmt.Errorf("cannot change proxy/VPN/DNS/version configuration while sing-box is running in %s mode", m.mode)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("proxy host is empty")
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && !ip.IsLoopback() {
		return fmt.Errorf("proxy host must be loopback-only")
	}
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid proxy port %d", port)
	}
	if dnsProvider != "cloudflare" && dnsProvider != "google" {
		return fmt.Errorf("unsupported DNS provider %q", dnsProvider)
	}
	if strings.TrimSpace(version) == "" {
		return fmt.Errorf("sing-box version is empty")
	}
	m.cfg.Host = host
	m.cfg.Port = port
	m.cfg.VPNInterface = vpnInterface
	m.cfg.DNSProvider = dnsProvider
	m.cfg.SingBoxVer = version
	return nil
}
