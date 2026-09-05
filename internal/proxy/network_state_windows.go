//go:build windows

package proxy

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

func capturePlatformNetworkSnapshot(ctx context.Context) (NetworkSnapshot, error) {
	s := emptySnapshot()
	if out, err := exec.CommandContext(ctx, "route", "print", "-4").CombinedOutput(); err == nil {
		s.RoutesV4 = normalizedLines(string(out))
	} else {
		return s, fmt.Errorf("route print -4: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "route", "print", "-6").CombinedOutput(); err == nil {
		s.RoutesV6 = normalizedLines(string(out))
	} else {
		return s, fmt.Errorf("route print -6: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "ipconfig", "/all").CombinedOutput(); err == nil {
		s.DNSFingerprint = fingerprint(string(out))
	}
	if out, err := exec.CommandContext(ctx, "netsh", "advfirewall", "show", "allprofiles").CombinedOutput(); err == nil {
		s.FirewallFingerprint = fingerprint(string(out))
	}
	return s, nil
}

func recoverPlatformOwnedNetworkState(ctx context.Context, j TunnelStateJournal) ([]string, error) {
	_ = ctx
	var actions []string
	if _, err := net.InterfaceByName(agentTunName); err == nil {
		return actions, fmt.Errorf("stale %s still exists on Windows; automatic deletion is intentionally disabled because interface ownership cannot yet be proven strongly enough", agentTunName)
	}
	// Wintun interface-scoped routes normally disappear with the transient TUN.
	// We still persist before/active route fingerprints, but do not issue broad
	// route delete commands on Windows until route ownership is tied to a stable
	// interface LUID/table contract.
	actions = append(actions, "previous helper is gone and antigravity-tun is absent; Windows route state left untouched")
	if j.Owned.FirewallChanged {
		actions = append(actions, "firewall fingerprint changed; no automatic rollback without ownership proof")
	}
	if j.Owned.DNSChanged {
		actions = append(actions, "DNS fingerprint changed; no automatic rollback without ownership proof")
	}
	return actions, nil
}

func platformProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	out, err := exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(pid), "/FO", "CSV", "/NH").CombinedOutput()
	if err != nil {
		return false
	}
	text := strings.ToLower(string(out))
	return !strings.Contains(text, "no tasks are running") && strings.Contains(text, strconv.Itoa(pid))
}
