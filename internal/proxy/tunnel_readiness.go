package proxy

import (
	"context"
	"fmt"
	"strings"
)

// AgentTunnelReadiness is a read-only snapshot used by the UI/orchestrator
// before tearing down a currently healthy SAFE proxy. It deliberately keeps
// host privilege/capability validation separate from routing/topology preflight
// so the caller can show an actionable reason instead of a generic start error.
type AgentTunnelReadiness struct {
	OK        bool                       `json:"ok"`
	Binary    string                     `json:"binary,omitempty"`
	HostReady bool                       `json:"host_ready"`
	HostError string                     `json:"host_error,omitempty"`
	Preflight AgentTunnelPreflightReport `json:"preflight"`
}

func (r AgentTunnelReadiness) Summary() string {
	var parts []string
	if r.HostError != "" {
		parts = append(parts, r.HostError)
	}
	if !r.Preflight.OK {
		parts = append(parts, r.Preflight.BlockerSummary())
	}
	if len(parts) == 0 {
		if r.OK {
			return "Agent Tunnel host and routing preflight are ready"
		}
		return "Agent Tunnel readiness is incomplete"
	}
	return strings.Join(parts, "; ")
}

func (m *Manager) AgentTunnelReadiness(ctx context.Context) AgentTunnelReadiness {
	r := AgentTunnelReadiness{Preflight: m.AgentTunnelPreflight(ctx)}
	if !m.AgentTunnelSupported() {
		r.HostError = fmt.Sprintf("Agent Tunnel is unsupported on this platform: %s", m.AgentTunnelPrivilegeHint())
		return r
	}

	r.Binary = m.Find()
	if strings.TrimSpace(r.Binary) == "" {
		r.HostError = "managed sing-box is not installed yet; use Install / verify first"
		return r
	}
	if err := validateAgentTunnelHost(r.Binary); err != nil {
		r.HostError = err.Error()
		return r
	}
	r.HostReady = true
	r.OK = r.Preflight.OK
	return r
}
