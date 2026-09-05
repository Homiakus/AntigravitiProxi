package app

import (
	"strings"
	"testing"

	"github.com/Homiakus/AntigravitiProxi/internal/antigravity"
	"github.com/Homiakus/AntigravitiProxi/internal/proxy"
)

func TestClassifyIsolationPolicy(t *testing.T) {
	cases := []struct {
		name     string
		active   bool
		fallback bool
		want     IsolationState
	}{
		{name: "inactive", active: false, fallback: false, want: IsolationInactive},
		{name: "inactive-ignores-fallback", active: false, fallback: true, want: IsolationInactive},
		{name: "strict-process-policy", active: true, fallback: false, want: IsolationStrict},
		{name: "domain-fallback-relaxes-isolation", active: true, fallback: true, want: IsolationRelaxed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, detail := classifyIsolationPolicy(tc.active, tc.fallback)
			if got != tc.want {
				t.Fatalf("isolation=%q want=%q detail=%q", got, tc.want, detail)
			}
			if strings.TrimSpace(detail) == "" {
				t.Fatal("isolation classification must explain its policy state")
			}
		})
	}
}

func TestClassifyNetworkAttestation(t *testing.T) {
	base := NetworkAttestationReport{
		ProcessTree: antigravity.ProcessTreeReport{
			Complete:  true,
			Processes: []antigravity.ProcessInfo{{PID: 101, Name: "Antigravity.exe", Known: true}},
		},
		Route: proxy.RouteAttestation{
			Available:      true,
			AgentObserved:  1,
			AgentVPNDirect: 1,
		},
		PIDRoute: proxy.PIDRouteAttestation{
			Available:           true,
			CandidatePIDs:       []int{101},
			ActiveCandidatePIDs: []int{101},
			VPNDirectPIDs:       []int{101},
		},
		Egress: proxy.PublicEgressAttestation{Available: true, CoverageComplete: true},
	}

	cases := []struct {
		name   string
		active bool
		mutate func(*NetworkAttestationReport)
		want   AssuranceState
	}{
		{name: "inactive", active: false, want: AssuranceIdle},
		{name: "verified", active: true, want: AssuranceVerified},
		{name: "incomplete-tree", active: true, mutate: func(r *NetworkAttestationReport) { r.ProcessTree.Complete = false }, want: AssuranceDegraded},
		{name: "unknown-helper", active: true, mutate: func(r *NetworkAttestationReport) {
			r.ProcessTree.UnknownHelpers = []antigravity.ProcessInfo{{PID: 102, Known: false}}
		}, want: AssuranceDegraded},
		{name: "unreviewed-endpoint", active: true, mutate: func(r *NetworkAttestationReport) {
			r.ProcessTree.LearnedEndpoints = []string{"new-backend.example"}
		}, want: AssuranceDegraded},
		{name: "unexpected-runtime-route", active: true, mutate: func(r *NetworkAttestationReport) { r.Route.AgentUnexpected = 1; r.Route.Detail = "unexpected" }, want: AssuranceDegraded},
		{name: "unexpected-pid-route", active: true, mutate: func(r *NetworkAttestationReport) {
			r.PIDRoute.UnexpectedPIDs = []int{101}
			r.PIDRoute.Detail = "unexpected pid"
		}, want: AssuranceDegraded},
		{name: "ambiguous-owner", active: true, mutate: func(r *NetworkAttestationReport) {
			r.PIDRoute.AmbiguousConnections = 1
			r.PIDRoute.Detail = "ambiguous"
		}, want: AssuranceDegraded},
		{name: "no-process", active: true, mutate: func(r *NetworkAttestationReport) { r.ProcessTree.Processes = nil }, want: AssurancePartial},
		{name: "route-unavailable", active: true, mutate: func(r *NetworkAttestationReport) { r.Route.Available = false }, want: AssurancePartial},
		{name: "idle-process", active: true, mutate: func(r *NetworkAttestationReport) {
			r.PIDRoute.ActiveCandidatePIDs = nil
			r.PIDRoute.VPNDirectPIDs = nil
		}, want: AssurancePartial},
		{name: "active-not-all-vpn", active: true, mutate: func(r *NetworkAttestationReport) {
			r.PIDRoute.ActiveCandidatePIDs = []int{101, 102}
			r.PIDRoute.VPNDirectPIDs = []int{101}
		}, want: AssuranceDegraded},
		{name: "observer-unavailable", active: true, mutate: func(r *NetworkAttestationReport) { r.Egress.Available = false }, want: AssurancePartial},
		{name: "observer-coverage-incomplete", active: true, mutate: func(r *NetworkAttestationReport) { r.Egress.CoverageComplete = false }, want: AssurancePartial},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			// Copy slices that a mutation may replace; all test mutations replace
			// rather than edit elements, so a shallow struct copy is sufficient.
			if tc.mutate != nil {
				tc.mutate(&r)
			}
			got, detail := classifyNetworkAttestation(tc.active, r)
			if got != tc.want {
				t.Fatalf("state=%q want=%q detail=%q", got, tc.want, detail)
			}
			if strings.TrimSpace(detail) == "" {
				t.Fatal("classification must always explain its evidence state")
			}
		})
	}
}

func TestVerifiedRouteEvidenceDoesNotHideRelaxedIsolation(t *testing.T) {
	state, detail := classifyNetworkAttestation(true, NetworkAttestationReport{
		ProcessTree: antigravity.ProcessTreeReport{
			Complete:  true,
			Processes: []antigravity.ProcessInfo{{PID: 101, Name: "Antigravity.exe", Known: true}},
		},
		Route: proxy.RouteAttestation{Available: true, AgentObserved: 1, AgentVPNDirect: 1},
		PIDRoute: proxy.PIDRouteAttestation{
			Available:           true,
			CandidatePIDs:       []int{101},
			ActiveCandidatePIDs: []int{101},
			VPNDirectPIDs:       []int{101},
		},
		Egress: proxy.PublicEgressAttestation{Available: true, CoverageComplete: true},
	})
	if state != AssuranceVerified {
		t.Fatalf("route evidence state=%q want verified; detail=%q", state, detail)
	}
	isolation, isolationDetail := classifyIsolationPolicy(true, true)
	if isolation != IsolationRelaxed {
		t.Fatalf("domain fallback isolation=%q want=%q", isolation, IsolationRelaxed)
	}
	if !strings.Contains(strings.ToLower(isolationDetail), "domain fallback") {
		t.Fatalf("relaxed isolation detail does not name cause: %q", isolationDetail)
	}
}
