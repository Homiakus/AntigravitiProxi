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

func TestVirtualNetworkManagerMatrix(t *testing.T) {
	cases := map[string]string{
		"docker0":  "Docker/container bridge",
		"br-a1b2":  "Docker/container bridge",
		"podman0":  "Podman/CNI",
		"cni0":     "Podman/CNI",
		"virbr0":   "libvirt",
		"vboxnet0": "VirtualBox",
		"vmnet8":   "VMware",
		"eth0":     "",
	}
	for iface, want := range cases {
		if got := virtualNetworkManager(iface); got != want {
			t.Errorf("virtualNetworkManager(%q)=%q want %q", iface, got, want)
		}
	}
}

func TestLikelyVPNMatrix(t *testing.T) {
	for _, iface := range []string{"amn0", "wg0", "tun99", "tailscale0", "wintun0", "eth0"} {
		want := iface != "eth0"
		if got := likelyVPNName(iface); got != want {
			t.Errorf("likelyVPNName(%q)=%v want %v", iface, got, want)
		}
	}
}
