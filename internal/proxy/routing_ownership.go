package proxy

import (
	"runtime"
	"sort"
	"strconv"
)

// Linux Agent Tunnel owns a deliberately explicit iproute2 namespace instead
// of accepting sing-box defaults. Preflight proves this namespace is empty
// before mutation; crash recovery is then allowed to clean only this reserved
// table/rule range. This is materially safer than attributing every before/after
// difference to AntigravitiProxi.
const (
	linuxTunnelRouteTableIndex = 20229
	linuxTunnelRuleStart       = 19000
	linuxTunnelRuleEnd         = 19031
)

func reservedPlatformOwnership() OwnedNetworkDelta {
	d := OwnedNetworkDelta{TunnelInterface: agentTunName}
	if runtime.GOOS != "linux" {
		return d
	}
	table := strconv.Itoa(linuxTunnelRouteTableIndex)
	d.NewRouteTablesV4 = []string{table}
	d.NewRouteTablesV6 = []string{table}
	for p := linuxTunnelRuleStart; p <= linuxTunnelRuleEnd; p++ {
		d.NewRulePrioritiesV4 = append(d.NewRulePrioritiesV4, p)
		d.NewRulePrioritiesV6 = append(d.NewRulePrioritiesV6, p)
	}
	return d
}

func mergeOwnedNetworkDelta(base, observed OwnedNetworkDelta) OwnedNetworkDelta {
	out := base
	if out.TunnelInterface == "" {
		out.TunnelInterface = observed.TunnelInterface
	}
	out.NewRouteTablesV4 = mergeStrings(out.NewRouteTablesV4, observed.NewRouteTablesV4)
	out.NewRouteTablesV6 = mergeStrings(out.NewRouteTablesV6, observed.NewRouteTablesV6)
	out.NewRulePrioritiesV4 = mergeInts(out.NewRulePrioritiesV4, observed.NewRulePrioritiesV4)
	out.NewRulePrioritiesV6 = mergeInts(out.NewRulePrioritiesV6, observed.NewRulePrioritiesV6)
	out.DNSChanged = out.DNSChanged || observed.DNSChanged
	out.FirewallChanged = out.FirewallChanged || observed.FirewallChanged
	return out
}

func mergeStrings(a, b []string) []string {
	seen := map[string]bool{}
	for _, v := range a {
		seen[v] = true
	}
	for _, v := range b {
		seen[v] = true
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func mergeInts(a, b []int) []int {
	seen := map[int]bool{}
	for _, v := range a {
		seen[v] = true
	}
	for _, v := range b {
		seen[v] = true
	}
	out := make([]int, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}
