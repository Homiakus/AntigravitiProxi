package proxy

import (
	"context"
	"fmt"
	"sort"
	"time"
)

type PIDRouteConnection struct {
	RuntimeConnection
	OwnerPIDs []int  `json:"owner_pids,omitempty"`
	Ownership string `json:"ownership"`
	Detail    string `json:"detail,omitempty"`
}

type PIDRouteAttestation struct {
	Available            bool                 `json:"available"`
	ObservedAt           time.Time            `json:"observed_at"`
	CandidatePIDs        []int                `json:"candidate_pids,omitempty"`
	Connections          []PIDRouteConnection `json:"connections,omitempty"`
	ActiveCandidatePIDs  []int                `json:"active_candidate_pids,omitempty"`
	VPNDirectPIDs        []int                `json:"vpn_direct_pids,omitempty"`
	UnexpectedPIDs       []int                `json:"unexpected_pids,omitempty"`
	AmbiguousConnections int                  `json:"ambiguous_connections"`
	UnresolvedAgentPaths []string             `json:"unresolved_agent_paths,omitempty"`
	Detail               string               `json:"detail"`
}

// AttestAgentPIDRoutes joins sing-box's live connection tracker with operating
// system socket ownership. The caller supplies the current Antigravity process
// tree PIDs, so this package does not depend on the higher-level antigravity
// package. A connection owned by one of those PIDs is checked regardless of the
// process-path string that sing-box reports; this is important for newly named
// helpers that are not yet in the static path allowlist.
//
// Candidate PIDs with no current socket are not failures: an idle helper has no
// egress to attest. Ambiguous socket ownership or an Antigravity-looking live
// connection that cannot be joined to a candidate PID is retained as explicit
// incomplete evidence and must not be promoted to verified assurance.
func (m *Manager) AttestAgentPIDRoutes(ctx context.Context, candidatePIDs []int) PIDRouteAttestation {
	r := PIDRouteAttestation{
		ObservedAt:    time.Now().UTC(),
		CandidatePIDs: uniqueSortedPositiveInts(candidatePIDs),
	}
	if len(r.CandidatePIDs) == 0 {
		r.Detail = "no Antigravity candidate PIDs supplied"
		return r
	}
	connections, err := m.RuntimeConnections(ctx)
	if err != nil {
		r.Detail = err.Error()
		return r
	}
	r.Available = true

	active := map[int]bool{}
	vpn := map[int]bool{}
	unexpected := map[int]bool{}
	unresolvedPath := map[string]bool{}

	for _, c := range connections {
		owners, detail, err := platformRuntimeConnectionOwners(c.Source, c.Network, r.CandidatePIDs)
		e := PIDRouteConnection{RuntimeConnection: c, OwnerPIDs: owners, Detail: detail}
		if err != nil {
			e.Ownership = "unresolved"
			e.Detail = err.Error()
		} else {
			switch len(owners) {
			case 0:
				e.Ownership = "unresolved"
			case 1:
				e.Ownership = "exact"
				pid := owners[0]
				active[pid] = true
				if c.Outbound == "vpn-direct" {
					vpn[pid] = true
				} else {
					unexpected[pid] = true
				}
			default:
				e.Ownership = "ambiguous"
				r.AmbiguousConnections++
			}
		}
		if e.Ownership == "unresolved" && looksLikeAntigravityProcess(c.Process) && c.Process != "" {
			unresolvedPath[c.Process] = true
		}
		r.Connections = append(r.Connections, e)
	}

	r.ActiveCandidatePIDs = sortedIntKeys(active)
	r.VPNDirectPIDs = sortedIntKeys(vpn)
	r.UnexpectedPIDs = sortedIntKeys(unexpected)
	for path := range unresolvedPath {
		r.UnresolvedAgentPaths = append(r.UnresolvedAgentPaths, path)
	}
	sort.Strings(r.UnresolvedAgentPaths)

	switch {
	case len(r.UnexpectedPIDs) > 0:
		r.Detail = fmt.Sprintf("%d active Antigravity PID(s) have at least one connection outside vpn-direct", len(r.UnexpectedPIDs))
	case r.AmbiguousConnections > 0 || len(r.UnresolvedAgentPaths) > 0:
		r.Detail = fmt.Sprintf("PID route evidence incomplete: ambiguous=%d unresolved_agent_paths=%d", r.AmbiguousConnections, len(r.UnresolvedAgentPaths))
	case len(r.ActiveCandidatePIDs) == 0:
		r.Detail = "connection tracker is available; supplied Antigravity PIDs currently have no attributable live connections"
	default:
		r.Detail = fmt.Sprintf("all %d active attributable Antigravity PID(s) use vpn-direct", len(r.ActiveCandidatePIDs))
	}
	return r
}

func uniqueSortedPositiveInts(in []int) []int {
	seen := map[int]bool{}
	for _, v := range in {
		if v > 0 {
			seen[v] = true
		}
	}
	return sortedIntKeys(seen)
}

func sortedIntKeys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for v := range m {
		if v > 0 {
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}
