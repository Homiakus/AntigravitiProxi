//go:build windows

package proxy

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	windowsNetstatMu    sync.Mutex
	windowsNetstatCache = map[string]struct {
		out string
		at  time.Time
	}{}
)

func getWindowsNetstatOutput(proto string) (string, error) {
	windowsNetstatMu.Lock()
	defer windowsNetstatMu.Unlock()
	now := time.Now()
	if cached, ok := windowsNetstatCache[proto]; ok && now.Sub(cached.at) < 1500*time.Millisecond {
		return cached.out, nil
	}
	out, err := exec.Command("netstat", "-ano", "-p", proto).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("netstat -ano -p %s: %w: %s", proto, err, strings.TrimSpace(string(out)))
	}
	s := string(out)
	windowsNetstatCache[proto] = struct {
		out string
		at  time.Time
	}{out: s, at: now}
	return s, nil
}

func platformRuntimeConnectionOwners(source, network string, candidatePIDs []int) ([]int, string, error) {
	wantIP, wantPort, err := splitWindowsRuntimeSource(source)
	if err != nil {
		return nil, "", err
	}
	proto := strings.ToLower(strings.TrimSpace(network))
	if proto != "tcp" && proto != "udp" {
		if proto == "" {
			proto = "tcp"
		} else {
			return nil, "", fmt.Errorf("unsupported runtime network %q", network)
		}
	}
	out, err := getWindowsNetstatOutput(proto)
	if err != nil {
		return nil, "", err
	}
	owners, matches := parseWindowsNetstatOwners(out, proto, wantIP, wantPort, candidatePIDs)
	return owners, fmt.Sprintf("source=%s matched %d netstat row(s) and %d candidate PID(s)", source, matches, len(owners)), nil
}

// parseWindowsNetstatOwners is intentionally pure so Windows-specific socket
// ownership can be fixture-tested on a hosted Windows runner. The platform
// command remains only an evidence collector; all matching semantics live here.
func parseWindowsNetstatOwners(raw, proto string, wantIP net.IP, wantPort int, candidatePIDs []int) ([]int, int) {
	proto = strings.ToLower(strings.TrimSpace(proto))
	candidates := map[int]bool{}
	for _, pid := range uniqueSortedPositiveInts(candidatePIDs) {
		candidates[pid] = true
	}
	owners := map[int]bool{}
	matches := 0
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.EqualFold(fields[0], proto) {
			continue
		}
		localIP, localPort, err := splitWindowsRuntimeSource(fields[1])
		if err != nil || localPort != wantPort || !localIP.Equal(wantIP) {
			continue
		}
		pid, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil || pid <= 0 {
			continue
		}
		matches++
		if candidates[pid] {
			owners[pid] = true
		}
	}
	return sortedIntKeys(owners), matches
}

func splitWindowsRuntimeSource(source string) (net.IP, int, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(source))
	if err != nil {
		return nil, 0, fmt.Errorf("parse runtime source %q: %w", source, err)
	}
	host = strings.Trim(host, "[]")
	if i := strings.LastIndex(host, "%"); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("runtime source %q does not contain an IP address", source)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return nil, 0, fmt.Errorf("runtime source %q has invalid port", source)
	}
	return ip, port, nil
}
