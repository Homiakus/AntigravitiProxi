//go:build linux

package proxy

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func processOwnsTCPListener(pid int, host string, port int) (bool, string, error) {
	inodes, err := processSocketInodes(pid)
	if err != nil {
		return false, "", fmt.Errorf("inspect /proc/%d/fd: %w", pid, err)
	}
	if len(inodes) == 0 {
		return false, "process owns no visible socket descriptors", nil
	}

	ips, err := expectedLoopbackIPs(host)
	if err != nil {
		return false, "", err
	}
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		matches, readErr := matchingListenInodes(table, port, ips)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			return false, "", readErr
		}
		for inode, addr := range matches {
			if _, ok := inodes[inode]; ok {
				return true, fmt.Sprintf("pid=%d owns LISTEN %s inode=%s", pid, addr, inode), nil
			}
		}
	}
	return false, fmt.Sprintf("pid=%d has sockets but none own expected LISTEN port %d", pid, port), nil
}

func processSocketInodes(pid int) (map[string]struct{}, error) {
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{})
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			out[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = struct{}{}
		}
	}
	return out, nil
}

func expectedLoopbackIPs(host string) ([]net.IP, error) {
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

func matchingListenInodes(path string, port int, expected []net.IP) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := make(map[string]string)
	s := bufio.NewScanner(f)
	first := true
	for s.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(s.Text())
		if len(fields) < 10 || fields[3] != "0A" { // TCP_LISTEN
			continue
		}
		ip, p, err := decodeProcEndpoint(fields[1])
		if err != nil || p != port || !containsIP(expected, ip) {
			continue
		}
		out[fields[9]] = net.JoinHostPort(ip.String(), strconv.Itoa(p))
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeProcEndpoint(raw string) (net.IP, int, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("invalid proc endpoint %q", raw)
	}
	port64, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return nil, 0, err
	}
	b, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, 0, err
	}
	switch len(b) {
	case 4:
		b[0], b[3] = b[3], b[0]
		b[1], b[2] = b[2], b[1]
	case 16:
		// /proc/net/tcp6 stores each 32-bit word in host byte order.
		for i := 0; i < 16; i += 4 {
			b[i], b[i+3] = b[i+3], b[i]
			b[i+1], b[i+2] = b[i+2], b[i+1]
		}
	default:
		return nil, 0, fmt.Errorf("unexpected proc address length %d", len(b))
	}
	return net.IP(b), int(port64), nil
}

func containsIP(expected []net.IP, got net.IP) bool {
	for _, ip := range expected {
		if ip.Equal(got) {
			return true
		}
	}
	return false
}
