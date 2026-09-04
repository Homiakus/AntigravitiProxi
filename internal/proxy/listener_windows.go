//go:build windows

package proxy

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

func processOwnsTCPListener(pid int, host string, port int) (bool, string, error) {
	out, err := exec.Command("netstat", "-ano", "-p", "tcp").CombinedOutput()
	if err != nil {
		return false, "", fmt.Errorf("netstat -ano -p tcp: %w: %s", err, strings.TrimSpace(string(out)))
	}
	expected, err := windowsExpectedListenerHosts(host)
	if err != nil {
		return false, "", err
	}
	wantPID := strconv.Itoa(pid)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.EqualFold(fields[0], "TCP") {
			continue
		}
		if fields[len(fields)-1] != wantPID || !strings.EqualFold(fields[len(fields)-2], "LISTENING") {
			continue
		}
		local := fields[1]
		h, p, splitErr := net.SplitHostPort(local)
		if splitErr != nil {
			continue
		}
		pn, convErr := strconv.Atoi(p)
		if convErr != nil || pn != port || !windowsHostMatches(expected, h) {
			continue
		}
		return true, fmt.Sprintf("pid=%d owns LISTEN %s", pid, local), nil
	}
	return false, fmt.Sprintf("pid=%d has no LISTEN socket on %s:%d", pid, host, port), nil
}

func windowsExpectedListenerHosts(host string) ([]net.IP, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			return nil, fmt.Errorf("listener host %q is not loopback", host)
		}
		return []net.IP{ip}, nil
	}
	if !strings.EqualFold(host, "localhost") {
		return nil, fmt.Errorf("unsupported listener host %q", host)
	}
	return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, nil
}

func windowsHostMatches(expected []net.IP, raw string) bool {
	raw = strings.Trim(raw, "[]")
	got := net.ParseIP(raw)
	if got == nil {
		return false
	}
	for _, ip := range expected {
		if ip.Equal(got) {
			return true
		}
	}
	return false
}
