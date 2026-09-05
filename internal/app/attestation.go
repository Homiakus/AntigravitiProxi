package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/antigravity"
	"github.com/Homiakus/AntigravitiProxi/internal/proxy"
)

type AssuranceState string

type IsolationState string

const (
	AssuranceIdle     AssuranceState = "idle"
	AssurancePartial  AssuranceState = "partial"
	AssuranceVerified AssuranceState = "verified"
	AssuranceDegraded AssuranceState = "degraded"

	IsolationInactive IsolationState = "inactive"
	IsolationStrict   IsolationState = "strict"
	IsolationRelaxed  IsolationState = "isolation-relaxed"
)

type NetworkAttestationReport struct {
	State                 AssuranceState                `json:"state"`
	Isolation             IsolationState                `json:"isolation"`
	IsolationDetail       string                        `json:"isolation_detail"`
	DomainFallbackEnabled bool                          `json:"domain_fallback_enabled"`
	ObservedAt            time.Time                     `json:"observed_at"`
	ProcessTree           antigravity.ProcessTreeReport `json:"process_tree"`
	Route                 proxy.RouteAttestation        `json:"route"`
	PIDRoute              proxy.PIDRouteAttestation     `json:"pid_route"`
	Egress                proxy.PublicEgressAttestation `json:"egress"`
	EgressCached          bool                          `json:"egress_cached"`
	EgressFreshUntil      *time.Time                    `json:"egress_fresh_until,omitempty"`
	Detail                string                        `json:"detail"`
}

// networkAttestation composes independent evidence instead of treating one
// green signal as proof of the whole transport path. Public observers are only
// queried when there is an attributable live Agent connection, avoiding
// unnecessary privacy-sensitive/network-dependent work while the IDE is idle.
// External evidence is short-lived and its cache/freshness is surfaced to the
// caller so UI/automation never mistakes a cached observation for a new probe.
func (s *Server) networkAttestation(ctx context.Context) NetworkAttestationReport {
	r := NetworkAttestationReport{ObservedAt: time.Now().UTC()}
	tunnelActive := s.pm.Mode() == proxy.ModeAgentTunnel && s.pm.AgentTunnelActive()
	if !tunnelActive {
		r.Isolation, r.IsolationDetail = classifyIsolationPolicy(false, false)
		r.State, r.Detail = classifyNetworkAttestation(false, r)
		return r
	}

	settings := s.Settings()
	r.DomainFallbackEnabled = settings.TunnelDomainFallback
	r.Isolation, r.IsolationDetail = classifyIsolationPolicy(true, settings.TunnelDomainFallback)

	r.ProcessTree = antigravity.DiscoverAgentProcessTree()
	pids := make([]int, 0, len(r.ProcessTree.Processes))
	for _, p := range r.ProcessTree.Processes {
		if p.PID > 0 {
			pids = append(pids, p.PID)
		}
	}
	r.Route = s.pm.AttestAgentRoutes(ctx)
	r.PIDRoute = s.pm.AttestAgentPIDRoutes(ctx, pids)
	if len(r.PIDRoute.ActiveCandidatePIDs) > 0 {
		var freshUntil time.Time
		r.Egress, freshUntil, r.EgressCached = s.cachedPublicEgress(ctx)
		if !freshUntil.IsZero() {
			fresh := freshUntil
			r.EgressFreshUntil = &fresh
		}
	} else {
		r.Egress.Detail = "external egress not probed because no attributable live Antigravity connection is active"
	}
	r.State, r.Detail = classifyNetworkAttestation(true, r)
	if r.State == AssuranceVerified && r.Isolation == IsolationRelaxed {
		r.Detail += "; Antigravity egress is verified, but domain fallback relaxes unrelated-process isolation for target Google domains"
	}
	return r
}

// classifyIsolationPolicy is deliberately separate from route assurance.
// A known Antigravity PID can have a fully proven vpn-direct path while broad
// domain fallback simultaneously weakens isolation for unrelated applications.
// Conflating those dimensions would either hide policy relaxation or make
// transport evidence impossible to interpret.
func classifyIsolationPolicy(tunnelActive, domainFallback bool) (IsolationState, string) {
	if !tunnelActive {
		return IsolationInactive, "Agent Tunnel is inactive; no TUN process-isolation policy is applied"
	}
	if domainFallback {
		return IsolationRelaxed, "domain fallback is enabled: target Google domains may use vpn-direct even when process identity is not attributed"
	}
	return IsolationStrict, "domain fallback is disabled: vpn-direct selection is restricted to explicit process/path policy and local-mixed traffic"
}

// classifyNetworkAttestation is deliberately pure: policy decisions can be
// regression-tested independently from platform routing and public observers.
// Strong verification requires complete identity, exact socket ownership,
// vpn-direct for every active attributed PID, and fresh external egress
// evidence. Missing evidence is partial; contradictory/ambiguous evidence is
// degraded.
func classifyNetworkAttestation(tunnelActive bool, r NetworkAttestationReport) (AssuranceState, string) {
	if !tunnelActive {
		return AssuranceIdle, "Agent Tunnel is not active"
	}
	if !r.ProcessTree.Complete {
		return AssuranceDegraded, "Antigravity process-tree inventory is incomplete: " + r.ProcessTree.Detail
	}
	if len(r.ProcessTree.UnknownHelpers) > 0 {
		return AssuranceDegraded, fmt.Sprintf("%d unknown Antigravity descendant(s) require explicit review", len(r.ProcessTree.UnknownHelpers))
	}
	if len(r.ProcessTree.LearnedEndpoints) > 0 {
		return AssuranceDegraded, fmt.Sprintf("%d backend endpoint candidate(s) require reviewed routing policy", len(r.ProcessTree.LearnedEndpoints))
	}
	if r.Route.Available && r.Route.AgentUnexpected > 0 {
		return AssuranceDegraded, r.Route.Detail
	}
	if r.PIDRoute.Available && len(r.PIDRoute.UnexpectedPIDs) > 0 {
		return AssuranceDegraded, r.PIDRoute.Detail
	}
	if r.PIDRoute.Available && (r.PIDRoute.AmbiguousConnections > 0 || len(r.PIDRoute.UnresolvedAgentPaths) > 0) {
		return AssuranceDegraded, r.PIDRoute.Detail
	}
	if len(r.ProcessTree.Processes) == 0 {
		return AssurancePartial, "Agent Tunnel is active, but no running Antigravity process tree is available to attest"
	}
	if !r.Route.Available || !r.PIDRoute.Available {
		return AssurancePartial, "Agent Tunnel is active, but live route/PID evidence is not currently available"
	}
	if len(r.PIDRoute.ActiveCandidatePIDs) == 0 {
		return AssurancePartial, "Antigravity processes are present but currently have no attributable live network connection"
	}
	if len(r.PIDRoute.VPNDirectPIDs) != len(r.PIDRoute.ActiveCandidatePIDs) {
		return AssuranceDegraded, "not every active attributable Antigravity PID is proven on vpn-direct"
	}
	if !r.Egress.Available {
		return AssurancePartial, "PID and route evidence is healthy, but external egress observation is unavailable"
	}
	if !r.Egress.CoverageComplete {
		return AssurancePartial, "external egress is observed, but independent IPv4/IPv6 TCP/UDP/QUIC coverage is incomplete"
	}
	return AssuranceVerified, fmt.Sprintf("%d active Antigravity PID(s) are exactly attributed to vpn-direct and external VPN egress is observable", len(r.PIDRoute.ActiveCandidatePIDs))
}

func (s *Server) handleNetworkAttestation(w http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), 18*time.Second)
	defer cancel()
	writeJSON(w, s.networkAttestation(ctx))
}
