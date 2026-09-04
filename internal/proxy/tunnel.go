package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

const agentTunnelTag = "agent-tun"

// AgentTunnelOptions controls the transparent fallback used when Antigravity's
// agent executor bypasses HTTP_PROXY/HTTPS_PROXY. TUN receives the transport
// at the OS routing layer, while process and narrow destination rules decide
// which flows are pinned to the selected VPN interface.
type AgentTunnelOptions struct {
	ProcessNames       []string
	ProcessPathRegex   []string
	TargetDomains      []string
	TargetDomainSuffix []string
	StrictRoute        bool
	DomainFallback     bool
}

func DefaultAgentTunnelOptions() AgentTunnelOptions {
	return AgentTunnelOptions{
		ProcessNames: []string{
			"Antigravity.exe",
			"antigravity.exe",
			"antigravity",
			"antigravity-desktop",
			"language_server.exe",
			"language_server_windows_x64.exe",
			"language_server_windows_arm64.exe",
			"language_server_linux_x64",
			"language_server_linux_arm64",
			"language_server",
			"agy.exe",
			"agy",
		},
		// Bundled node/helper processes are caught by installation path instead
		// of routing every node.exe on the machine.
		ProcessPathRegex: []string{
			`(?i).*antigravity.*`,
			`(?i).*language[_-]?server.*`,
		},
		TargetDomains: []string{
			"antigravity.google",
			"accounts.google.com",
			"oauth2.googleapis.com",
			"cloudcode-pa.googleapis.com",
			"daily-cloudcode-pa.googleapis.com",
		},
		TargetDomainSuffix: []string{
			".googleapis.com",
		},
		StrictRoute:    false,
		DomainFallback: true,
	}
}

func (m *Manager) AgentTunnelSupported() bool {
	return runtime.GOOS == "windows" || runtime.GOOS == "linux"
}

func (m *Manager) AgentTunnelActive() bool {
	return m.TunnelRunning()
}

func (m *Manager) AgentTunnelPrivilegeHint() string {
	switch runtime.GOOS {
	case "windows":
		return "Agent Tunnel creates a system TUN interface and normally requires AntigravitiProxi to run as Administrator."
	case "linux":
		return "Agent Tunnel requires root or CAP_NET_ADMIN/CAP_NET_RAW for TUN and route management."
	default:
		return "Agent Tunnel is supported only on Windows and Linux."
	}
}

// StopAndWait switches modes safely without racing the sing-box wait goroutine.
func (m *Manager) StopAndWait(ctx context.Context) error {
	if err := m.Stop(); err != nil {
		return err
	}
	ticker := time.NewTicker(40 * time.Millisecond)
	defer ticker.Stop()
	for {
		if !m.ManagedRunning() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (m *Manager) WriteAgentTunnelConfig(options AgentTunnelOptions) error {
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()
	return writeAgentTunnelConfig(cfg, m.TunnelConfigPath(), options)
}

func writeAgentTunnelConfig(cfg Config, path string, options AgentTunnelOptions) error {
	if strings.TrimSpace(cfg.VPNInterface) == "" {
		return errors.New("Agent Tunnel requires an explicit VPN interface")
	}
	if err := os.MkdirAll(cfg.Root, 0o755); err != nil {
		return err
	}

	dnsIP, dnsName := "1.1.1.1", "cloudflare-dns.com"
	if strings.EqualFold(cfg.DNSProvider, "google") {
		dnsIP, dnsName = "8.8.8.8", "dns.google"
	}

	secureDoH := map[string]any{
		"type":           "https",
		"tag":            "secure-doh",
		"server":         dnsIP,
		"server_port":    443,
		"path":           "/dns-query",
		"bind_interface": cfg.VPNInterface,
		"tls": map[string]any{
			"enabled":     true,
			"server_name": dnsName,
		},
	}
	localDNS := map[string]any{
		"type":      "local",
		"tag":       "local-dns",
		"prefer_go": false,
	}

	dnsRules := []any{
		map[string]any{
			"process_name": options.ProcessNames,
			"action":       "route",
			"server":       "secure-doh",
		},
		map[string]any{
			"process_path_regex": options.ProcessPathRegex,
			"action":             "route",
			"server":             "secure-doh",
		},
	}
	if options.DomainFallback {
		dnsRules = append(dnsRules, map[string]any{
			"domain":        options.TargetDomains,
			"domain_suffix": options.TargetDomainSuffix,
			"action":        "route",
			"server":        "secure-doh",
		})
	}

	vpnDirect := map[string]any{
		"type":           "direct",
		"tag":            "vpn-direct",
		"bind_interface": cfg.VPNInterface,
		"domain_resolver": map[string]any{
			"server":   "secure-doh",
			"strategy": "ipv4_only",
		},
	}
	// auto_detect_interface makes this outbound escape the TUN through the
	// machine's original default route, preventing loops and preserving normal
	// behavior for Fusion 360 and unrelated applications.
	systemDirect := map[string]any{
		"type": "direct",
		"tag":  "system-direct",
		"domain_resolver": map[string]any{
			"server": "local-dns",
		},
	}

	tunInbound := map[string]any{
		"type":         "tun",
		"tag":          agentTunnelTag,
		"address":      []string{"172.31.255.1/30", "fdfe:dcba:9876::1/126"},
		"mtu":          1500,
		"auto_route":   true,
		"strict_route": options.StrictRoute,
		"dns_mode":     "hijack",
		"stack":        "system",
		"route_exclude_address": []string{
			"127.0.0.0/8",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16",
			"::1/128",
			"fe80::/10",
			"fc00::/7",
		},
	}
	if runtime.GOOS == "linux" {
		// Recommended by sing-box together with auto_route on Linux: nftables
		// pre-routing improves performance and avoids Docker route conflicts.
		tunInbound["auto_redirect"] = true
	}

	routeRules := []any{
		// Sniff TLS/HTTP/QUIC so an exact Antigravity destination can still be
		// identified when a future helper binary changes its process name.
		map[string]any{
			"inbound": []string{agentTunnelTag},
			"action":  "sniff",
		},
		// Keep the mixed port useful for HTTP/SOCKS diagnostics while TUN is on.
		map[string]any{
			"inbound":  []string{"local-mixed"},
			"action":   "route",
			"outbound": "vpn-direct",
		},
		map[string]any{
			"inbound":      []string{agentTunnelTag},
			"process_name": options.ProcessNames,
			"action":       "route",
			"outbound":     "vpn-direct",
		},
		map[string]any{
			"inbound":            []string{agentTunnelTag},
			"process_path_regex": options.ProcessPathRegex,
			"action":             "route",
			"outbound":           "vpn-direct",
		},
	}
	if options.DomainFallback {
		routeRules = append(routeRules, map[string]any{
			"inbound":       []string{agentTunnelTag},
			"domain":        options.TargetDomains,
			"domain_suffix": options.TargetDomainSuffix,
			"action":        "route",
			"outbound":      "vpn-direct",
		})
	}

	doc := map[string]any{
		"log": map[string]any{
			"level":     "info",
			"timestamp": true,
		},
		"dns": map[string]any{
			"servers":  []any{secureDoH, localDNS},
			"rules":    dnsRules,
			"final":    "local-dns",
			"strategy": "prefer_ipv4",
		},
		"inbounds": []any{
			map[string]any{
				"type":        "mixed",
				"tag":         "local-mixed",
				"listen":      cfg.Host,
				"listen_port": cfg.Port,
			},
			tunInbound,
		},
		"outbounds": []any{vpnDirect, systemDirect},
		"route": map[string]any{
			"rules":                 routeRules,
			"final":                 "system-direct",
			"auto_detect_interface": true,
		},
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// StartAgentTunnel accepts an optional options argument to keep compatibility
// with older callers while allowing the web UI to add strict/domain controls.
func (m *Manager) StartAgentTunnel(ctx context.Context, provided ...AgentTunnelOptions) error {
	if !m.AgentTunnelSupported() {
		return fmt.Errorf("Agent Tunnel is unsupported on %s", runtime.GOOS)
	}

	// Agent Tunnel relies on stable 1.14.0+ TUN DNS controls. Install() is
	// intentionally called even when some sing-box binary already exists so a
	// stale managed 1.13.x build is upgraded before config validation.
	if _, err := m.Install(ctx); err != nil {
		return fmt.Errorf("ensure Agent Tunnel sing-box: %w", err)
	}

	options := DefaultAgentTunnelOptions()
	if len(provided) > 0 {
		options = provided[0]
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil && m.cmd.Process != nil {
		return fmt.Errorf("sing-box already started by this process in %s mode; stop it before starting Agent Tunnel", m.mode)
	}
	if strings.TrimSpace(m.cfg.VPNInterface) == "" {
		return errors.New("Agent Tunnel requires an explicit VPN interface")
	}
	if err := writeAgentTunnelConfig(m.cfg, m.TunnelConfigPath(), options); err != nil {
		return err
	}
	return m.startLocked(ctx, m.TunnelConfigPath(), ModeAgentTunnel,
		fmt.Sprintf("Agent Tunnel started: TUN -> Antigravity process/domain policy -> %s; unrelated traffic -> system-direct", m.cfg.VPNInterface))
}
