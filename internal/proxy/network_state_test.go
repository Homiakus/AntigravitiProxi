package proxy

import "testing"

func TestDeriveOwnedNetworkDelta(t *testing.T) {
	before := NetworkSnapshot{
		RoutesV4: []string{"default via 10.0.0.1 dev eth0 table 100"},
		RulesV4:  []string{"1000: from all lookup 100"},
		DNSFingerprint: "dns-a",
		FirewallFingerprint: "fw-a",
	}
	after := NetworkSnapshot{
		RoutesV4: []string{
			"default via 10.0.0.1 dev eth0 table 100",
			"0.0.0.0/1 dev antigravity-tun table 2022",
			"128.0.0.0/1 dev antigravity-tun table 2022",
		},
		RulesV4: []string{
			"1000: from all lookup 100",
			"9000: from all lookup 2022",
		},
		DNSFingerprint: "dns-a",
		FirewallFingerprint: "fw-b",
	}

	d := deriveOwnedNetworkDelta(before, after)
	if len(d.NewRouteTablesV4) != 1 || d.NewRouteTablesV4[0] != "2022" {
		t.Fatalf("unexpected new route tables: %#v", d.NewRouteTablesV4)
	}
	if len(d.NewRulePrioritiesV4) != 1 || d.NewRulePrioritiesV4[0] != 9000 {
		t.Fatalf("unexpected new rule priorities: %#v", d.NewRulePrioritiesV4)
	}
	if d.DNSChanged {
		t.Fatal("DNS should not be marked changed")
	}
	if !d.FirewallChanged {
		t.Fatal("firewall fingerprint change should be recorded")
	}
}

func TestVerifyOwnedDeltaAbsent(t *testing.T) {
	owned := OwnedNetworkDelta{
		NewRouteTablesV4:    []string{"2022"},
		NewRulePrioritiesV4: []int{9000},
	}
	clean := NetworkSnapshot{
		RoutesV4: []string{"default via 10.0.0.1 dev eth0 table 100"},
		RulesV4:  []string{"1000: from all lookup 100"},
	}
	if err := verifyOwnedDeltaAbsent(clean, owned); err != nil {
		t.Fatalf("clean snapshot rejected: %v", err)
	}

	dirty := clean
	dirty.RulesV4 = append(dirty.RulesV4, "9000: from all lookup 2022")
	if err := verifyOwnedDeltaAbsent(dirty, owned); err == nil {
		t.Fatal("expected stale owned rule to be detected")
	}
}
