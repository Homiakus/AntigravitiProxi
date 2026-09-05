package app

import (
	"context"
	"fmt"
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
	State       AssuranceState                 `json:"state"`
	ObservedAt  time.Time                      `json:"observed_at"`
	ProcessTree antigravity.ProcessTreeReport  `json:"process_tree"`
	Route       proxy.RouteAttestation         `json:"route"`
	PIDRoute    proxy.PIDRouteAttestation      `json:"pid_route"`
	Egress      proxy.PublicEgressAttestation  `json:"egress"`
	Detail      string                         `json:"detail"`
}

// networkAttestation composes independent evidence instead of treating one
// green signal as proof of the whole transport path. In particular, external
// observer failure is "partial" evidence, not a claim that routing is wrong;
// an unexpected outbound or ambiguous PID/socket ownership is degraded.
func (s *Server) networkAttestation(ctx context.Context) NetworkAttestationReport {
	r := NetworkAttestationReport{
		State:      AssuranceIdle,
		ObservedAt: time.Now().UTC(),
	}
	if s.pm.Mode() != proxy.ModeAgentTunnel || !s.pm.AgentTunnelActive() {
		r.Detail = "Agent Tunnel is not active"
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
	r.Egress = s.pm.AttestPublicEgress(ctx)

	if !r.ProcessTree.Complete {
		r.State = AssuranceDegraded
		r.Detail = "Antigravity process-tree inventory is incomplete: " + r.ProcessTree.Detail
		return r
	}
	if len(r.ProcessTree.UnknownHelpers) > 0 {
		r.State = AssuranceDegraded
		r.Detail = fmt.Sprintf("%d unknown Antigravity descendant(s) require explicit review", len(r.ProcessTree.UnknownHelpers))
		return r
	}
	if r.Route.Available && r.Route.AgentUnexpected > 0 {
		r.State = AssuranceDegraded
		r.Detail = r.Route.Detail
		return r
	}
	if r.PIDRoute.Available && len(r.PIDRoute.UnexpectedPIDs) > 0 {
		r.State = AssuranceDegraded
		r.Detail = r.PIDRoute.Detail
		return r
	}
	if r.PIDRoute.Available && (r.PIDRoute.AmbiguousConnections > 0 || len(r.PIDRoute.UnresolvedAgentPaths) > 0) {
		r.State = AssuranceDegraded
		r.Detail = r.PIDRoute.Detail
		return r
	}
	if len(r.ProcessTree.Processes) == 0 {
		r.State = AssurancePartial
		r.Detail = "Agent Tunnel is active, but no running Antigravity process tree is available to attest"
		return r
	}
	if !r.Route.Available || !r.PIDRoute.Available {
		r.State = AssurancePartial
		r.Detail = "Agent Tunnel is active, but live route/PID evidence is not currently available"
		return r
	}
	if len(r.PIDRoute.ActiveCandidatePIDs) == 0 {
		r.State = AssurancePartial
		r.Detail = "Antigravity processes are present but currently have no attributable live network connection"
		return r
	}
	if !r.Egress.Available {
		r.State = AssurancePartial
		r.Detail = "PID and route evidence is healthy, but external egress observation is unavailable"
		return r
	}
	if len(r.PIDRoute.VPNDirectPIDs) != len(r.PIDRoute.ActiveCandidatePIDs) {
		r.State = AssuranceDegraded
		r.Detail = "not every active attributable Antigravity PID is proven on vpn-direct"
		return r
	}

	r.State = AssuranceVerified
	r.Detail = fmt.Sprintf("%d active Antigravity PID(s) are exactly attributed to vpn-direct and external VPN egress is observable", len(r.PIDRoute.ActiveCandidatePIDs))
	return r
}

func (s *Server) handleNetworkAttestation(w http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), 18*time.Second)
	defer cancel()
	writeJSON(w, s.networkAttestation(ctx))
}
