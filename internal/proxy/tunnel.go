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
	// Linux must actually bring ordinary local TCP/UDP connections through the
	// TUN before process_name/process_path policy can be authoritative. We use
	// strict routing on Linux and prove the negative invariant in CI: an
	// unrelated process still exits through system-direct. Windows keeps the
	// less intrusive default because strict_route can conflict with desktop
	// networking/VM software there.
	strictRoute := runtime.GOOS == "linux"

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
		StrictRoute:    strictRoute,
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
		return "Agent Tunnel requires a TUN-capable helper. For non-root operation grant managed sing-box CAP_NET_ADMIN,CAP_NET_RAW,CAP_SYS_PTRACE,CAP_DAC_READ_SEARCH so it can manage routes and attribute sockets to Antigravity processes."
	default:
		return "Agent Tunnel is supported only on Windows and Linux."
	}
}

// StopAndWait switches modes safely without racing the sing-box wait goroutine.
// Linux first sends SIGTERM so sing-box can remove routing state cleanly; if it
// does not exit before the caller's deadline we force-kill it as a fallback.
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
	// behavior for unrelated applications.
	systemDirect := map[string]any{
		"type": "direct",
		"tag":  "system-direct",
		"domain_resolver": map[string]any{
			"server": "local-dns",
		},
	}

	tunInbound := map[string]any{
		"type":           "tun",
		"tag":            agentTunnelTag,
		"interface_name": "antigravity-tun",
		"address":        []string{"172.31.255.1/30", "fdfe:dcba:9876::1/126"},
		"mtu":            1500,
		"auto_route":     true,
		"strict_route":   options.StrictRoute,
		"dns_mode":       "hijack",
		"stack":          "system",
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
		// Do NOT enable auto_redirect here. In sing-box 1.14 its fallback ip-rule
		// is intentionally checked after Linux main/default rules, so a valid host
		// default route can bypass the TUN before process policy is evaluated.
		// Agent Tunnel needs the opposite invariant: capture first, classify by
		// process/path second, then return unrelated traffic through system-direct.
		// Plain auto_route + strict_route gives us that capture model. CI has a
		// dual-egress test specifically to prevent this from regressing.
		tunInbound["auto_redirect"] = false
	}

	// Ordering is intentional. Since sing-box 1.14, routing rules also run in a
	// pre-match phase for L3 inbounds. TCP sniffing always stops pre-match because
	// no payload is available yet. Therefore process rules MUST precede sniff;
	// otherwise every TCP flow can reach sniff before process attribution and the
	// selective process policy is not authoritative.
	routeRules := []any{
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
		map[string]any{
			"inbound": []string{agentTunnelTag},
			"action":  "sniff",
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
	return atomicfile.Write(path, append(b, '\n'), 0o600)
}

// StartAgentTunnel accepts an optional options argument to keep compatibility
// with older callers while allowing the web UI to add strict/domain controls.
// Startup is transactional at the managed-process boundary: success is not
// reported until the TUN exists and the mixed listener is proven to belong to
// the newly started sing-box process. Failed readiness triggers rollback.
func (m *Manager) StartAgentTunnel(ctx context.Context, provided ...AgentTunnelOptions) error {
	if !m.AgentTunnelSupported() {
		return fmt.Errorf("Agent Tunnel is unsupported on %s", runtime.GOOS)
	}

	binary, err := m.Install(ctx)
	if err != nil {
		return fmt.Errorf("ensure Agent Tunnel sing-box: %w", err)
	}
	if err := validateAgentTunnelHost(binary); err != nil {
		return err
	}

	options := DefaultAgentTunnelOptions()
	if len(provided) > 0 {
		options = provided[0]
	}
	// Linux strict routing is not a preference: the dual-egress runtime test
	// proved it is required for authoritative host-flow capture before process
	// classification. Do not allow a UI/API false value to reintroduce bypass.
	if runtime.GOOS == "linux" {
		options.StrictRoute = true
	}

	m.mu.Lock()
	if m.cmd != nil && m.cmd.Process != nil {
		mode := m.mode
		m.mu.Unlock()
		return fmt.Errorf("sing-box already started by this process in %s mode; stop it before starting Agent Tunnel", mode)
	}
	vpn := strings.TrimSpace(m.cfg.VPNInterface)
	if vpn == "" {
		m.mu.Unlock()
		return errors.New("Agent Tunnel requires an explicit VPN interface")
	}
	if vpn == "antigravity-tun" {
		m.mu.Unlock()
		return errors.New("Agent Tunnel cannot use its own TUN interface as the VPN upstream")
	}
	iface, err := net.InterfaceByName(vpn)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("selected VPN interface %q does not exist: %w", vpn, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		m.mu.Unlock()
		return fmt.Errorf("selected VPN interface %q is down", vpn)
	}
	if err := writeAgentTunnelConfig(m.cfg, m.TunnelConfigPath(), options); err != nil {
		m.mu.Unlock()
		return err
	}
	err = m.startLocked(ctx, m.TunnelConfigPath(), ModeAgentTunnel,
		fmt.Sprintf("Agent Tunnel starting: TUN -> Antigravity process/domain policy -> %s; unrelated traffic -> system-direct", m.cfg.VPNInterface))
	m.mu.Unlock()
	if err != nil {
		return err
	}

	if err := m.waitAgentTunnelReady(ctx, 8*time.Second); err != nil {
		return m.rollbackFailedAgentTunnelStart(err)
	}
	m.log("info", "Agent Tunnel readiness proven: managed listener ownership + TUN interface")
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
		if iface, err := net.InterfaceByName("antigravity-tun"); err == nil && iface.Flags&net.FlagUp != 0 {
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.StopAndWait(ctx); err != nil {
		return fmt.Errorf("%w; rollback also failed: %v", cause, err)
	}
	if _, err := net.InterfaceByName("antigravity-tun"); err == nil {
		return fmt.Errorf("%w; rollback stopped sing-box but antigravity-tun still exists", cause)
	}
	return cause
}
