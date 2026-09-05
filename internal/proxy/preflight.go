package proxy

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strings"
	"time"
)

type PreflightSeverity string

const (
	PreflightInfo    PreflightSeverity = "info"
	PreflightWarning PreflightSeverity = "warning"
	PreflightBlocker PreflightSeverity = "blocker"
)

type PreflightFinding struct {
	Severity PreflightSeverity `json:"severity"`
	Code     string            `json:"code"`
	Detail   string            `json:"detail"`
}

type AgentTunnelPreflightReport struct {
	OK        bool               `json:"ok"`
	Platform  string             `json:"platform"`
	VPN       string             `json:"vpn_interface"`
	CheckedAt time.Time          `json:"checked_at"`
	Findings  []PreflightFinding `json:"findings"`
}

func (r AgentTunnelPreflightReport) BlockerSummary() string {
	var parts []string
	for _, f := range r.Findings {
		if f.Severity == PreflightBlocker {
			parts = append(parts, f.Code+": "+f.Detail)
		}
	}
	if len(parts) == 0 {
		return "no blockers"
	}
	return strings.Join(parts, "; ")
}

// AgentTunnelPreflight is intentionally read-only. It converts known host
// topology hazards into explicit evidence before any TUN/route mutation. Hard
// ownership ambiguity blocks startup; heterogeneous but non-overlapping network
// managers are warnings because Docker/VM/VPN coexistence is common and must be
// proven by runtime health rather than banned categorically.
func (m *Manager) AgentTunnelPreflight(ctx context.Context) AgentTunnelPreflightReport {
	cfg := m.Config()
	r := AgentTunnelPreflightReport{
		OK:        true,
		Platform:  runtime.GOOS,
		VPN:       strings.TrimSpace(cfg.VPNInterface),
		CheckedAt: time.Now().UTC(),
	}
	add := func(severity PreflightSeverity, code, detail string) {
		r.Findings = append(r.Findings, PreflightFinding{Severity: severity, Code: code, Detail: detail})
		if severity == PreflightBlocker {
			r.OK = false
		}
	}

	if r.VPN == "" {
		add(PreflightBlocker, "vpn.not_configured", "select an explicit VPN interface before Agent Tunnel startup")
	} else if r.VPN == agentTunName {
		add(PreflightBlocker, "vpn.recursive_tun", "the Agent Tunnel interface cannot be used as its own upstream")
	} else if iface, err := net.InterfaceByName(r.VPN); err != nil {
		add(PreflightBlocker, "vpn.not_found", fmt.Sprintf("selected VPN interface %q does not exist: %v", r.VPN, err))
	} else if iface.Flags&net.FlagUp == 0 {
		add(PreflightBlocker, "vpn.down", fmt.Sprintf("selected VPN interface %q is down", r.VPN))
	} else {
		add(PreflightInfo, "vpn.ready", fmt.Sprintf("selected upstream %q is present and UP", r.VPN))
	}

	if _, err := net.InterfaceByName(agentTunName); err == nil {
		add(PreflightBlocker, "tun.preexisting", agentTunName+" already exists before this operation; ownership is unknown")
	}

	snapshot, err := capturePlatformNetworkSnapshot(ctx)
	if err != nil {
		add(PreflightBlocker, "snapshot.failed", err.Error())
		return r
	}
	if err := preflightPlatformNetworkOwnership(snapshot); err != nil {
		add(PreflightBlocker, "routing.ownership_collision", err.Error())
	} else if runtime.GOOS == "linux" {
		add(PreflightInfo, "routing.namespace_free", fmt.Sprintf("reserved iproute2 table %d and priorities %d..%d are free", linuxTunnelRouteTableIndex, linuxTunnelRuleStart, linuxTunnelRuleEnd))
	}

	for _, f := range analyzeHostRouteConflicts(cfg, snapshot) {
		add(f.Severity, f.Code, f.Detail)
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		rank := func(s PreflightSeverity) int {
			switch s {
			case PreflightBlocker:
				return 0
			case PreflightWarning:
				return 1
			default:
				return 2
			}
		}
		if rank(r.Findings[i].Severity) != rank(r.Findings[j].Severity) {
			return rank(r.Findings[i].Severity) < rank(r.Findings[j].Severity)
		}
		return r.Findings[i].Code < r.Findings[j].Code
	})
	return r
}

func analyzeHostRouteConflicts(cfg Config, snapshot NetworkSnapshot) []PreflightFinding {
	if runtime.GOOS != "linux" {
		return nil
	}
	var out []PreflightFinding
	seen := map[string]bool{}
	add := func(code, detail string) {
		key := code + "|" + detail
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, PreflightFinding{Severity: PreflightWarning, Code: code, Detail: detail})
	}

	// Non-standard policy rules are not automatically conflicts. They are
	// surfaced because they are exactly the kind of host-specific state that can
	// reorder route lookup around a TUN. The reserved Agent Tunnel range itself
	// was already checked as a hard blocker above.
	for _, family := range []struct {
		name  string
		rules []string
	}{
		{name: "IPv4", rules: snapshot.RulesV4},
		{name: "IPv6", rules: snapshot.RulesV6},
	} {
		for _, line := range family.rules {
			p, ok := rulePriority(line)
			if !ok || p == 0 || p == 32766 || p == 32767 || (p >= linuxTunnelRuleStart && p <= linuxTunnelRuleEnd) {
				continue
			}
			add("routing.custom_policy_rule", fmt.Sprintf("%s custom policy rule priority %d is present: %s", family.name, p, line))
		}
	}

	ifaces, _ := net.Interfaces()
	selected := strings.ToLower(strings.TrimSpace(cfg.VPNInterface))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := strings.ToLower(iface.Name)
		if name == selected || name == agentTunName {
			continue
		}
		if manager := virtualNetworkManager(name); manager != "" {
			add("routing.virtual_network_manager", fmt.Sprintf("active interface %q suggests %s-managed routes; verify coexistence", iface.Name, manager))
		}
		if likelyVPNName(name) {
			add("routing.concurrent_vpn", fmt.Sprintf("another VPN-like interface %q is UP while %q is selected", iface.Name, cfg.VPNInterface))
		}
	}
	return out
}

func likelyVPNName(name string) bool {
	name = strings.ToLower(name)
	return strings.Contains(name, "amnezia") || strings.Contains(name, "vpn") || strings.Contains(name, "wireguard") || strings.HasPrefix(name, "wg") || strings.HasPrefix(name, "tun") || strings.Contains(name, "wintun") || strings.Contains(name, "tailscale") || strings.Contains(name, "outline")
}

func virtualNetworkManager(name string) string {
	name = strings.ToLower(name)
	switch {
	case name == "docker0" || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "docker"):
		return "Docker/container bridge"
	case strings.HasPrefix(name, "podman") || strings.HasPrefix(name, "cni"):
		return "Podman/CNI"
	case strings.HasPrefix(name, "virbr") || strings.Contains(name, "libvirt"):
		return "libvirt"
	case strings.HasPrefix(name, "vbox"):
		return "VirtualBox"
	case strings.HasPrefix(name, "vmnet"):
		return "VMware"
	default:
		return ""
	}
}
