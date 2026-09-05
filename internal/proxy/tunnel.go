package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/atomicfile"
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
	strictRoute := runtime.GOOS == "linux"
	return AgentTunnelOptions{
		ProcessNames: []string{
			"Antigravity.exe", "antigravity.exe", "antigravity", "antigravity-desktop",
			"language_server.exe", "language_server_windows_x64.exe", "language_server_windows_arm64.exe",
			"language_server_linux_x64", "language_server_linux_arm64", "language_server", "agy.exe", "agy",
		},
		ProcessPathRegex: []string{`(?i).*antigravity.*`, `(?i).*language[_-]?server.*`},
		TargetDomains: []string{
			"antigravity.google", "accounts.google.com", "oauth2.googleapis.com",
			"cloudcode-pa.googleapis.com", "daily-cloudcode-pa.googleapis.com",
		},
		TargetDomainSuffix: []string{".googleapis.com"},
		StrictRoute:        strictRoute,
		DomainFallback:     true,
	}
}

func (m *Manager) AgentTunnelSupported() bool { return runtime.GOOS == "windows" || runtime.GOOS == "linux" }
func (m *Manager) AgentTunnelActive() bool    { return m.TunnelRunning() }

func (m *Manager) AgentTunnelPrivilegeHint() string {
	switch runtime.GOOS {
	case "windows":
		return "Agent Tunnel creates a system TUN interface and normally requires AntigravitiProxi to run as Administrator."
	case "linux":
		return "Agent Tunnel keeps the control plane unprivileged. If TUN or managed sing-box capabilities are missing, AntigravitiProxi uses one fixed-function PolicyKit helper; the OS handles authentication and the helper re-verifies the managed binary before applying the exact required capabilities."
	default:
		return "Agent Tunnel is supported only on Windows and Linux."
	}
}

func (m *Manager) StopAndWait(ctx context.Context) error {
	hadTunnelState := m.Mode() == ModeAgentTunnel || m.NetworkJournalStatus().Open
	if err := m.Stop(); err != nil {
		return err
	}
	ticker := time.NewTicker(40 * time.Millisecond)
	defer ticker.Stop()
	for {
		if !m.ManagedRunning() {
			if hadTunnelState {
				if err := m.finishTunnelTransaction(ctx); err != nil {
					return fmt.Errorf("managed helper stopped but network-state recovery failed: %w", err)
				}
			}
			return nil
		}
		select {
		case <-ctx.Done():
			m.mu.Lock()
			cmd := m.cmd
			m.mu.Unlock()
			if cmd != nil && cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
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
	apiSecret, err := ensureAPISecret(cfg.Root)
	if err != nil {
		return err
	}
	dnsIP, dnsName := "1.1.1.1", "cloudflare-dns.com"
	if strings.EqualFold(cfg.DNSProvider, "google") {
		dnsIP, dnsName = "8.8.8.8", "dns.google"
	}
	secureDoH := map[string]any{
		"type": "https", "tag": "secure-doh", "server": dnsIP, "server_port": 443, "path": "/dns-query",
		"bind_interface": cfg.VPNInterface,
		"tls": map[string]any{"enabled": true, "server_name": dnsName},
	}
	localDNS := map[string]any{"type": "local", "tag": "local-dns", "prefer_go": false}
	dnsRules := []any{
		map[string]any{"process_name": options.ProcessNames, "action": "route", "server": "secure-doh"},
		map[string]any{"process_path_regex": options.ProcessPathRegex, "action": "route", "server": "secure-doh"},
	}
	if options.DomainFallback {
		dnsRules = append(dnsRules, map[string]any{
			"domain": options.TargetDomains, "domain_suffix": options.TargetDomainSuffix,
			"action": "route", "server": "secure-doh",
		})
	}
	vpnDirect := map[string]any{
		"type": "direct", "tag": "vpn-direct", "bind_interface": cfg.VPNInterface,
		"domain_resolver": map[string]any{"server": "secure-doh", "strategy": "ipv4_only"},
	}
	systemDirect := map[string]any{
		"type": "direct", "tag": "system-direct",
		"domain_resolver": map[string]any{"server": "local-dns"},
	}
	tunInbound := map[string]any{
		"type": "tun", "tag": agentTunnelTag, "interface_name": agentTunName,
		"address": []string{"172.31.255.1/30", "fdfe:dcba:9876::1/126"},
		"mtu": 1500, "auto_route": true, "strict_route": options.StrictRoute, "dns_mode": "hijack", "stack": "system",
		"route_exclude_address": []string{
			"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
			"::1/128", "fe80::/10", "fc00::/7",
		},
	}
	if runtime.GOOS == "linux" {
		tunInbound["auto_redirect"] = false
		tunInbound["iproute2_table_index"] = linuxTunnelRouteTableIndex
		tunInbound["iproute2_rule_index"] = linuxTunnelRuleStart
	}
	routeRules := []any{
		map[string]any{"inbound": []string{"local-mixed"}, "action": "route", "outbound": "vpn-direct"},
		map[string]any{"inbound": []string{agentTunnelTag}, "process_name": options.ProcessNames, "action": "route", "outbound": "vpn-direct"},
		map[string]any{"inbound": []string{agentTunnelTag}, "process_path_regex": options.ProcessPathRegex, "action": "route", "outbound": "vpn-direct"},
		map[string]any{"inbound": []string{agentTunnelTag}, "action": "sniff"},
	}
	if options.DomainFallback {
		routeRules = append(routeRules, map[string]any{
			"inbound": []string{agentTunnelTag}, "domain": options.TargetDomains,
			"domain_suffix": options.TargetDomainSuffix, "action": "route", "outbound": "vpn-direct",
		})
	}
	doc := map[string]any{
		"log": map[string]any{"level": "info", "timestamp": true},
		"dns": map[string]any{"servers": []any{secureDoH, localDNS}, "rules": dnsRules, "final": "local-dns", "strategy": "prefer_ipv4"},
		"inbounds": []any{
			map[string]any{"type": "mixed", "tag": "local-mixed", "listen": cfg.Host, "listen_port": cfg.Port},
			tunInbound,
		},
		"outbounds": []any{vpnDirect, systemDirect},
		"route": map[string]any{"rules": routeRules, "final": "system-direct", "auto_detect_interface": true},
		"services": []any{
			map[string]any{
				"type": "api", "tag": "agp-observe",
				"listen": singBoxAPIHost, "listen_port": singBoxAPIPort,
				"secret": apiSecret,
				"access_control_allow_origin": []string{"http://127.0.0.1", "http://localhost"},
				"access_control_allow_private_network": false,
				"dashboard": false,
			},
		},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, append(b, '\n'), 0o600)
}

func (m *Manager) StartAgentTunnel(ctx context.Context, provided ...AgentTunnelOptions) error {
	if !m.AgentTunnelSupported() {
		return fmt.Errorf("Agent Tunnel is unsupported on %s", runtime.GOOS)
	}
	binary, err := m.InstallVerified(ctx)
	if err != nil {
		return fmt.Errorf("ensure verified Agent Tunnel sing-box: %w", err)
	}
	if err := validateAgentTunnelHost(binary); err != nil {
		return err
	}
	options := DefaultAgentTunnelOptions()
	if len(provided) > 0 {
		options = provided[0]
	}
	if runtime.GOOS == "linux" {
		options.StrictRoute = true
	}
	if m.ManagedRunning() {
		return fmt.Errorf("sing-box already started by this process in %s mode; stop it before starting Agent Tunnel", m.Mode())
	}

	preflight := m.AgentTunnelPreflight(ctx)
	for _, finding := range preflight.Findings {
		level := "info"
		if finding.Severity == PreflightWarning {
			level = "warn"
		} else if finding.Severity == PreflightBlocker {
			level = "error"
		}
		m.log(level, "Agent Tunnel preflight ["+finding.Code+"]: "+finding.Detail)
	}
	if !preflight.OK {
		return fmt.Errorf("Agent Tunnel preflight blocked startup: %s", preflight.BlockerSummary())
	}

	cfg := m.Config()
	vpn := strings.TrimSpace(cfg.VPNInterface)
	if vpn == "" {
		return errors.New("Agent Tunnel requires an explicit VPN interface")
	}
	if vpn == agentTunName {
		return errors.New("Agent Tunnel cannot use its own TUN interface as the VPN upstream")
	}
	iface, err := net.InterfaceByName(vpn)
	if err != nil {
		return fmt.Errorf("selected VPN interface %q does not exist: %w", vpn, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("selected VPN interface %q is down", vpn)
	}
	if err := m.beginTunnelTransaction(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	if m.cmd != nil && m.cmd.Process != nil {
		mode := m.mode
		m.mu.Unlock()
		m.abortPreparedTunnelTransaction("managed process appeared during startup transaction")
		return fmt.Errorf("sing-box concurrently started in %s mode", mode)
	}
	if err := writeAgentTunnelConfig(m.cfg, m.TunnelConfigPath(), options); err != nil {
		m.mu.Unlock()
		m.abortPreparedTunnelTransaction("config write failed: " + err.Error())
		return err
	}
	err = m.startLocked(ctx, m.TunnelConfigPath(), ModeAgentTunnel,
		fmt.Sprintf("Agent Tunnel starting: TUN -> Antigravity process/domain policy -> %s; unrelated traffic -> system-direct", m.cfg.VPNInterface))
	m.mu.Unlock()
	if err != nil {
		m.abortPreparedTunnelTransaction("sing-box start failed: " + err.Error())
		return err
	}
	if err := m.waitAgentTunnelReady(ctx, 8*time.Second); err != nil {
		return m.rollbackFailedAgentTunnelStart(err)
	}
	if err := m.markTunnelActive(ctx); err != nil {
		return m.rollbackFailedAgentTunnelStart(fmt.Errorf("persist active network-state evidence: %w", err))
	}
	m.log("info", "Agent Tunnel readiness proven: managed listener ownership + TUN interface + durable route/rule fingerprint")
	return nil
}

func (m *Manager) waitAgentTunnelReady(ctx context.Context, maxWait time.Duration) error {
	deadline := time.NewTimer(maxWait)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	last := "waiting for managed listener and TUN"
	for {
		if !m.ManagedRunning() {
			return errors.New("sing-box exited before Agent Tunnel readiness was established")
		}
		tunOK := false
		if iface, err := net.InterfaceByName(agentTunName); err == nil && iface.Flags&net.FlagUp != 0 {
			tunOK = true
		}
		listenerOK, detail := m.ManagedListenerOwned()
		if tunOK && listenerOK {
			return nil
		}
		last = fmt.Sprintf("tun_up=%v listener_owned=%v (%s)", tunOK, listenerOK, detail)
		select {
		case <-ctx.Done():
			return fmt.Errorf("Agent Tunnel readiness cancelled: %w; last=%s", ctx.Err(), last)
		case <-deadline.C:
			return fmt.Errorf("Agent Tunnel readiness timeout after %s; last=%s", maxWait, last)
		case <-ticker.C:
		}
	}
}

func (m *Manager) rollbackFailedAgentTunnelStart(cause error) error {
	m.log("error", "Agent Tunnel readiness failed; rolling back: "+cause.Error())
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := m.StopAndWait(ctx); err != nil {
		return fmt.Errorf("%w; rollback also failed: %v", cause, err)
	}
	if _, err := net.InterfaceByName(agentTunName); err == nil {
		return fmt.Errorf("%w; rollback stopped sing-box but %s still exists", cause, agentTunName)
	}
	return cause
}
