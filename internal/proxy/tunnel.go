package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const agentTunnelTag = "agent-tun"

// AgentTunnelSupported reports whether the current platform is supported by
// the sing-box TUN + process matcher combination used by AntigravitiProxi.
func (m *Manager) AgentTunnelSupported() bool {
	return runtime.GOOS == "windows" || runtime.GOOS == "linux"
}

// AgentTunnelActive is intentionally derived from both the live mixed-port
// health check and the active config. This remains useful after a UI refresh
// without introducing another persisted mode flag.
func (m *Manager) AgentTunnelActive() bool {
	if !m.Running() {
		return false
	}
	b, err := os.ReadFile(m.ConfigPath())
	if err != nil {
		return false
	}
	return bytes.Contains(b, []byte(`"tag": "`+agentTunnelTag+`"`))
}

func (m *Manager) AgentTunnelPrivilegeHint() string {
	switch runtime.GOOS {
	case "windows":
		return "Agent Tunnel changes system routes and normally requires running AntigravitiProxi as Administrator."
	case "linux":
		return "Agent Tunnel requires root or CAP_NET_ADMIN/CAP_NET_RAW for the TUN interface and route management."
	default:
		return "Agent Tunnel is supported only on Windows and Linux."
	}
}

// StopAndWait stops a managed sing-box instance and waits for Manager.cmd to
// be released by the wait goroutine. This is used when switching between the
// lightweight mixed proxy and the privileged Agent Tunnel configuration.
func (m *Manager) StopAndWait(ctx context.Context) error {
	m.mu.Lock()
	cmd := m.cmd
	m.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	_ = cmd.Process.Kill()

	ticker := time.NewTicker(40 * time.Millisecond)
	defer ticker.Stop()
	for {
		m.mu.Lock()
		done := m.cmd == nil
		m.mu.Unlock()
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// StartAgentTunnel starts sing-box with BOTH the existing local mixed proxy
// and a TUN inbound. The TUN captures the transport path that some Antigravity
// helper processes can use while ignoring HTTP_PROXY. Routing remains
// process-aware: Antigravity/language-server traffic is forced to the selected
// VPN interface, while unrelated applications are sent to a system-direct
// outbound. Target Google DNS names use secure DoH; unrelated DNS falls back
// to the local resolver.
func (m *Manager) StartAgentTunnel(ctx context.Context) error {
	if !m.AgentTunnelSupported() {
		return fmt.Errorf("Agent Tunnel is unsupported on %s", runtime.GOOS)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil && m.cmd.Process != nil {
		return errors.New("sing-box is already started by this process; stop it before enabling Agent Tunnel")
	}
	if strings.TrimSpace(m.cfg.VPNInterface) == "" {
		return errors.New("Agent Tunnel requires an explicit VPN interface")
	}
	p := m.Find()
	if p == "" {
		return errors.New("sing-box not installed")
	}
	if err := writeAgentTunnelConfig(m.cfg, m.ConfigPath()); err != nil {
		return err
	}

	check := exec.CommandContext(ctx, p, "check", "-c", m.ConfigPath())
	if out, err := check.CombinedOutput(); err != nil {
		return fmt.Errorf("sing-box Agent Tunnel config check failed: %v: %s", err, strings.TrimSpace(string(out)))
	}

	logf, err := os.OpenFile(m.LogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	errF, err := os.OpenFile(m.ErrPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		_ = logf.Close()
		return err
	}

	cmd := exec.Command(p, "run", "-c", m.ConfigPath())
	cmd.Stdout = logf
	cmd.Stderr = errF
	if err = cmd.Start(); err != nil {
		_ = logf.Close()
		_ = errF.Close()
		return fmt.Errorf("start Agent Tunnel: %w; %s", err, m.AgentTunnelPrivilegeHint())
	}
	m.cmd = cmd

	go func() {
		err := cmd.Wait()
		_ = logf.Close()
		_ = errF.Close()
		m.mu.Lock()
		if m.cmd == cmd {
			m.cmd = nil
		}
		m.mu.Unlock()
		if err != nil {
			m.log("error", "Agent Tunnel sing-box exited: "+err.Error())
		} else {
			m.log("info", "Agent Tunnel stopped")
		}
	}()

	m.log("warn", fmt.Sprintf("Agent Tunnel started: TUN + process-aware routing via %s", m.cfg.VPNInterface))
	return nil
}

func writeAgentTunnelConfig(cfg Config, path string) error {
	if err := os.MkdirAll(cfg.Root, 0o755); err != nil {
		return err
	}

	dnsIP, dnsName := "1.1.1.1", "cloudflare-dns.com"
	if strings.EqualFold(cfg.DNSProvider, "google") {
		dnsIP, dnsName = "8.8.8.8", "dns.google"
	}

	secureDoH := map[string]any{
		"type":        "https",
		"tag":         "secure-doh",
		"server":      dnsIP,
		"server_port": 443,
		"path":        "/dns-query",
		"tls": map[string]any{
			"enabled":     true,
			"server_name": dnsName,
		},
		"bind_interface": cfg.VPNInterface,
	}
	localDNS := map[string]any{
		"type":      "local",
		"tag":       "system-local",
		"prefer_go": true,
	}

	agentDirect := map[string]any{
		"type":           "direct",
		"tag":            "agent-vpn",
		"bind_interface": cfg.VPNInterface,
		"domain_resolver": map[string]any{
			"server":   "secure-doh",
			"strategy": "ipv4_only",
		},
	}
	systemDirect := map[string]any{
		"type": "direct",
		"tag":  "system-direct",
	}

	tunInbound := map[string]any{
		"type":                  "tun",
		"tag":                   agentTunnelTag,
		"interface_name":        "antigravity-tun",
		"address":               []string{"172.31.255.1/30", "fdfe:dcba:9876:1::1/126"},
		"mtu":                   1500,
		"auto_route":            true,
		"strict_route":          false,
		"route_exclude_address": []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"},
	}
	if runtime.GOOS == "linux" {
		// Recommended by sing-box for Linux when auto_route is enabled.
		tunInbound["auto_redirect"] = true
	}

	// Process names intentionally avoid globally matching node/node.exe. Bundled
	// Node helpers are covered by process_path_regex, while a generic node
	// process is only routed through the VPN when the sniffed destination belongs
	// to the Google/Antigravity domain set below.
	agentProcessNames := []string{
		"Antigravity.exe",
		"antigravity.exe",
		"antigravity",
		"antigravity-desktop",
		"language_server.exe",
		"language_server_windows_x64.exe",
		"language_server_windows_arm64.exe",
		"language_server_linux_x64",
		"language_server_linux_arm64",
		"agy.exe",
		"agy",
	}
	agentPathRegex := []string{
		`(?i).*[/\\]antigravity[/\\].*`,
		`(?i).*[/\\]google[/\\]antigravity[/\\].*`,
		`(?i).*[/\\]\.gemini[/\\](?:antigravity|antigravity-ide)[/\\].*`,
	}
	googleDomainSuffixes := []string{
		"googleapis.com",
		"googleusercontent.com",
		"antigravity.google",
	}
	googleExactDomains := []string{
		"accounts.google.com",
		"oauth2.googleapis.com",
		"cloudcode-pa.googleapis.com",
		"daily-cloudcode-pa.googleapis.com",
	}

	doc := map[string]any{
		"log": map[string]any{
			"level":     "info",
			"timestamp": true,
		},
		"dns": map[string]any{
			"servers": []any{secureDoH, localDNS},
			"rules": []any{
				map[string]any{
					"domain_suffix": googleDomainSuffixes,
					"action":        "route",
					"server":        "secure-doh",
				},
				map[string]any{
					"domain": googleExactDomains,
					"action": "route",
					"server": "secure-doh",
				},
			},
			"final":    "system-local",
			"strategy": "ipv4_only",
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
		"outbounds": []any{agentDirect, systemDirect},
		"route": map[string]any{
			"auto_detect_interface": true,
			"rules": []any{
				map[string]any{"action": "sniff"},
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				map[string]any{
					"process_name": agentProcessNames,
					"action":       "route",
					"outbound":     "agent-vpn",
				},
				map[string]any{
					"process_path_regex": agentPathRegex,
					"action":             "route",
					"outbound":           "agent-vpn",
				},
				map[string]any{
					"type": "logical",
					"mode": "and",
					"rules": []any{
						map[string]any{"process_name": []string{"node.exe", "node"}},
						map[string]any{
							"type": "logical",
							"mode": "or",
							"rules": []any{
								map[string]any{"domain_suffix": googleDomainSuffixes},
								map[string]any{"domain": googleExactDomains},
							},
						},
					},
					"action":   "route",
					"outbound": "agent-vpn",
				},
			},
			"final": "system-direct",
		},
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
