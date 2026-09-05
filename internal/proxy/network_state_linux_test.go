//go:build linux

package proxy

import "testing"

func TestPreflightPlatformNetworkOwnershipRejectsReservedRouteTable(t *testing.T) {
	s := NetworkSnapshot{
		RoutesV4: []string{"default via 10.0.0.1 dev eth0 table 20229"},
	}
	if err := preflightPlatformNetworkOwnership(s); err == nil {
		t.Fatal("expected reserved route table collision to be rejected")
	}
}

func TestPreflightPlatformNetworkOwnershipRejectsReservedRulePriority(t *testing.T) {
	s := NetworkSnapshot{
		RulesV6: []string{"19005: from all lookup 20229"},
	}
	if err := preflightPlatformNetworkOwnership(s); err == nil {
		t.Fatal("expected reserved rule priority collision to be rejected")
	}
}

func TestPreflightPlatformNetworkOwnershipAllowsUnrelatedRoutingState(t *testing.T) {
	s := NetworkSnapshot{
		RoutesV4: []string{"default via 10.0.0.1 dev eth0 table 100"},
		RoutesV6: []string{"default via fe80::1 dev eth0 table 200"},
		RulesV4:  []string{"1000: from all lookup 100"},
		RulesV6:  []string{"32766: from all lookup main"},
	}
	if err := preflightPlatformNetworkOwnership(s); err != nil {
		t.Fatalf("unrelated routing state rejected: %v", err)
	}
}

func TestReservedPlatformOwnershipCoversConfiguredLinuxNamespace(t *testing.T) {
	d := reservedPlatformOwnership()
	if len(d.NewRouteTablesV4) != 1 || d.NewRouteTablesV4[0] != "20229" {
		t.Fatalf("unexpected IPv4 route table ownership: %#v", d.NewRouteTablesV4)
	}
	if len(d.NewRouteTablesV6) != 1 || d.NewRouteTablesV6[0] != "20229" {
		t.Fatalf("unexpected IPv6 route table ownership: %#v", d.NewRouteTablesV6)
	}
	want := linuxTunnelRuleEnd - linuxTunnelRuleStart + 1
	if len(d.NewRulePrioritiesV4) != want || len(d.NewRulePrioritiesV6) != want {
		t.Fatalf("reserved rule range incomplete: v4=%d v6=%d want=%d", len(d.NewRulePrioritiesV4), len(d.NewRulePrioritiesV6), want)
	}
	if d.NewRulePrioritiesV4[0] != linuxTunnelRuleStart || d.NewRulePrioritiesV4[len(d.NewRulePrioritiesV4)-1] != linuxTunnelRuleEnd {
		t.Fatalf("unexpected IPv4 priority bounds: %#v", d.NewRulePrioritiesV4)
	}
}
