//go:build linux

package proxy

import (
	"reflect"
	"testing"
)

func TestMissingLinuxCapabilitiesAcceptsFullSet(t *testing.T) {
	got := missingLinuxCapabilities("/tmp/sing-box cap_dac_read_search,cap_net_admin,cap_net_raw,cap_sys_ptrace=ep")
	if len(got) != 0 {
		t.Fatalf("missing=%v want none", got)
	}
}

func TestMissingLinuxCapabilitiesReportsExactMissingSet(t *testing.T) {
	got := missingLinuxCapabilities("/tmp/sing-box cap_net_admin,cap_net_raw=ep")
	want := []string{"cap_sys_ptrace", "cap_dac_read_search"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missing=%v want %v", got, want)
	}
}

func TestLinuxCapabilitySpecContainsEveryRequiredCapability(t *testing.T) {
	if got := missingLinuxCapabilities(linuxTunnelCapabilitySpec); len(got) != 0 {
		t.Fatalf("capability spec is incomplete, missing=%v", got)
	}
}
