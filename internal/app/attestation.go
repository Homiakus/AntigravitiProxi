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

const (
	AssuranceIdle     AssuranceState = "idle"
	AssurancePartial  AssuranceState = "partial"
	AssuranceVerified AssuranceState = "verified"
	AssuranceDegraded AssuranceState = "degraded"
)

type NetworkAttestationReport struct {
	State            AssuranceState                `json:"state"`
	ObservedAt       time.Time                     `json:"observed_at"`
	ProcessTree      antigravity.ProcessTreeReport `json:"process_tree"`
	Route            proxy.RouteAttestation        `json:"route"`
	PIDRoute         proxy.PIDRouteAttestation     `json:"pid_route"`
	Egress           proxy.PublicEgressAttestation `json:"egress"`
	EgressCached     bool                          `json:"egress_cached"`
	EgressFreshUntil *time.Time                    `json:"egress_fresh_until,omitempty"`
	Detail           string                        `json:"detail"`
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
		r.State, r.Detail = classifyNetworkAttestation(false, r)
		return r
	}

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
	return r
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
	return AssuranceVerified, fmt.Sprintf("%d active Antigravity PID(s) are exactly attributed to vpn-direct and external VPN egress is observable", len(r.PIDRoute.ActiveCandidatePIDs))
}

func (s *Server) handleNetworkAttestation(w http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), 18*time.Second)
	defer cancel()
	writeJSON(w, s.networkAttestation(ctx))
}
