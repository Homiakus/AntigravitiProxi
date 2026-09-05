//go:build linux

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func capturePlatformNetworkSnapshot(ctx context.Context) (NetworkSnapshot, error) {
	s := emptySnapshot()
	var err error
	if s.RoutesV4, err = commandLines(ctx, "ip", "-o", "-4", "route", "show", "table", "all"); err != nil {
		return s, err
	}
	if s.RoutesV6, err = commandLines(ctx, "ip", "-o", "-6", "route", "show", "table", "all"); err != nil {
		return s, err
	}
	if s.RulesV4, err = commandLines(ctx, "ip", "-o", "-4", "rule", "show"); err != nil {
		return s, err
	}
	if s.RulesV6, err = commandLines(ctx, "ip", "-o", "-6", "rule", "show"); err != nil {
		return s, err
	}

	var dnsParts []string
	if b, readErr := os.ReadFile("/etc/resolv.conf"); readErr == nil {
		dnsParts = append(dnsParts, string(b))
	}
	if _, lookErr := exec.LookPath("resolvectl"); lookErr == nil {
		if out, cmdErr := exec.CommandContext(ctx, "resolvectl", "dns").CombinedOutput(); cmdErr == nil {
			dnsParts = append(dnsParts, string(out))
		}
	}
	if len(dnsParts) > 0 {
		s.DNSFingerprint = fingerprint(dnsParts...)
	}

	if _, lookErr := exec.LookPath("nft"); lookErr == nil {
		if out, cmdErr := exec.CommandContext(ctx, "nft", "list", "ruleset").CombinedOutput(); cmdErr == nil {
			s.FirewallFingerprint = fingerprint(string(out))
		}
	}
	return s, nil
}

// preflightPlatformNetworkOwnership proves the routing namespace reserved for
// Agent Tunnel is empty before sing-box is allowed to mutate host networking.
// This converts recovery from heuristic ownership inference into a fail-closed
// contract: anything found in table 20229 or priority range 19000..19031 was
// not created by the new operation and therefore blocks startup.
func preflightPlatformNetworkOwnership(before NetworkSnapshot) error {
	reservedTable := strconv.Itoa(linuxTunnelRouteTableIndex)
	for _, family := range []struct {
		name   string
		routes []string
	}{
		{name: "IPv4", routes: before.RoutesV4},
		{name: "IPv6", routes: before.RoutesV6},
	} {
		for _, line := range family.routes {
			if routeTable(line) == reservedTable {
				return fmt.Errorf("reserved Linux %s route table %s is already occupied: %s", family.name, reservedTable, line)
			}
		}
	}

	for _, family := range []struct {
		name  string
		rules []string
	}{
		{name: "IPv4", rules: before.RulesV4},
		{name: "IPv6", rules: before.RulesV6},
	} {
		for _, line := range family.rules {
			priority, ok := rulePriority(line)
			if ok && priority >= linuxTunnelRuleStart && priority <= linuxTunnelRuleEnd {
				return fmt.Errorf("reserved Linux %s rule priority %d is already occupied: %s", family.name, priority, line)
			}
		}
	}
	return nil
}

func commandLines(ctx context.Context, name string, args ...string) ([]string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return normalizedLines(string(out)), nil
}

func recoverPlatformOwnedNetworkState(ctx context.Context, j TunnelStateJournal) ([]string, error) {
	var actions []string
	if _, err := net.InterfaceByName(agentTunName); err == nil {
		out, delErr := exec.CommandContext(ctx, "ip", "link", "delete", agentTunName).CombinedOutput()
		if delErr != nil {
			return actions, fmt.Errorf("delete owned TUN %s: %w: %s", agentTunName, delErr, strings.TrimSpace(string(out)))
		}
		actions = append(actions, "deleted owned TUN interface "+agentTunName)
	}

	for _, p := range j.Owned.NewRulePrioritiesV4 {
		if err := deleteRulePriority(ctx, "-4", p); err != nil {
			return actions, err
		}
		actions = append(actions, fmt.Sprintf("removed owned IPv4 rule priority %d if present", p))
	}
	for _, p := range j.Owned.NewRulePrioritiesV6 {
		if err := deleteRulePriority(ctx, "-6", p); err != nil {
			return actions, err
		}
		actions = append(actions, fmt.Sprintf("removed owned IPv6 rule priority %d if present", p))
	}
	for _, table := range j.Owned.NewRouteTablesV4 {
		if err := flushRouteTable(ctx, "-4", table); err != nil {
			return actions, err
		}
		actions = append(actions, "flushed owned IPv4 route table "+table)
	}
	for _, table := range j.Owned.NewRouteTablesV6 {
		if err := flushRouteTable(ctx, "-6", table); err != nil {
			return actions, err
		}
		actions = append(actions, "flushed owned IPv6 route table "+table)
	}

	// Current Agent Tunnel deliberately uses auto_redirect=false and does not
	// own the host firewall or resolver configuration. Fingerprint changes are
	// retained as evidence but never auto-restored because another network
	// manager may legitimately have changed them while the tunnel was active.
	if j.Owned.FirewallChanged {
		actions = append(actions, "firewall fingerprint changed during operation; left untouched because ownership is not proven")
	}
	if j.Owned.DNSChanged {
		actions = append(actions, "DNS fingerprint changed during operation; left untouched because ownership is not proven")
	}
	return actions, nil
}

func deleteRulePriority(ctx context.Context, family string, priority int) error {
	// A clean shutdown needs no elevated mutation. In particular, ip rule del
	// may return EPERM for an absent rule when the manager is an ordinary user.
	lines, err := commandLines(ctx, "ip", "-o", family, "rule", "show")
	if err != nil {
		return err
	}
	present := false
	for _, line := range lines {
		if p, ok := rulePriority(line); ok && p == priority {
			present = true
			break
		}
	}
	if !present {
		return nil
	}

	// A priority can theoretically contain multiple rules. The entire configured
	// range was proven empty before this operation, so any rule that later
	// appears inside it belongs to this Agent Tunnel transaction.
	for i := 0; i < 8; i++ {
		out, err := exec.CommandContext(ctx, "ip", family, "rule", "del", "priority", strconv.Itoa(priority)).CombinedOutput()
		if err != nil {
			text := strings.ToLower(string(out))
			if strings.Contains(text, "no such file") || strings.Contains(text, "not found") || strings.Contains(text, "cannot find") || len(strings.TrimSpace(string(out))) == 0 {
				return nil
			}
			return fmt.Errorf("delete %s rule priority %d: %w: %s", family, priority, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func flushRouteTable(ctx context.Context, family, table string) error {
	lines, inspectErr := commandLines(ctx, "ip", "-o", family, "route", "show", "table", "all")
	if inspectErr != nil {
		return inspectErr
	}
	present := false
	for _, line := range lines {
		if routeTable(line) == table {
			present = true
			break
		}
	}
	if !present {
		return nil
	}

	out, err := exec.CommandContext(ctx, "ip", family, "route", "flush", "table", table).CombinedOutput()
	if err == nil {
		return nil
	}
	text := strings.ToLower(string(out))
	if strings.Contains(text, "fib table does not exist") || strings.Contains(text, "no such file") || strings.Contains(text, "not found") {
		return nil
	}
	return fmt.Errorf("flush %s route table %s: %w: %s", family, table, err, strings.TrimSpace(string(out)))
}

func platformProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.Stat("/proc/" + strconv.Itoa(pid))
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

// tryPrivilegedNetworkRecovery is only a fallback for the narrow case where
// the ordinary-user control plane cannot remove state created by the
// capability-bearing sing-box. The privileged entry point validates the
// journal again and can touch only the reserved Agent Tunnel namespace.
func (m *Manager) tryPrivilegedNetworkRecovery(ctx context.Context, cause error) ([]string, error) {
	if !networkMutationPermissionError(cause.Error()) {
		return nil, cause
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve control-plane executable for privileged recovery: %w", err)
	}
	if err := runLinuxPrivilegeBroker(self, "__linux-privileged-recover", m.networkJournalPath()); err != nil {
		return nil, err
	}
	return []string{"privileged helper removed reserved Agent Tunnel network state"}, nil
}

func networkMutationPermissionError(detail string) bool {
	detail = strings.ToLower(detail)
	return strings.Contains(detail, "operation not permitted") ||
		strings.Contains(detail, "permission denied") ||
		strings.Contains(detail, "eperm")
}
