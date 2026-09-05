//go:build linux

package proxy

import "testing"

func TestAnalyzeHostRouteConflictsSurfacesCustomPolicyRule(t *testing.T) {
	s := NetworkSnapshot{RulesV4: []string{
		"0: from all lookup local",
		"4242: from all lookup 4242",
		"32766: from all lookup main",
		"32767: from all lookup default",
	}}
	findings := analyzeHostRouteConflicts(Config{VPNInterface: "vpn0"}, s)
	found := false
	for _, f := range findings {
		if f.Code == "routing.custom_policy_rule" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("custom policy rule was not surfaced: %#v", findings)
	}
}

func TestAnalyzeHostRouteConflictsDoesNotWarnForStandardRulesOnly(t *testing.T) {
	s := NetworkSnapshot{RulesV4: []string{
		"0: from all lookup local",
		"32766: from all lookup main",
		"32767: from all lookup default",
	}}
	findings := analyzeHostRouteConflicts(Config{}, s)
	for _, f := range findings {
		if f.Code == "routing.custom_policy_rule" {
			t.Fatalf("standard rule was misclassified: %#v", findings)
		}
	}
}
