//go:build linux

package proxy

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func platformRuntimeConnectionOwners(source, network string, candidatePIDs []int) ([]int, string, error) {
	ip, port, err := splitRuntimeSource(source)
	if err != nil {
		return nil, "", err
	}
	tables := linuxSocketTables(network)
	if len(tables) == 0 {
		return nil, "", fmt.Errorf("unsupported runtime network %q", network)
	}

	matchingInodes := map[string]struct{}{}
	for _, table := range tables {
		inodes, err := linuxSourceSocketInodes(table, ip, port)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, "", err
		}
		for inode := range inodes {
			matchingInodes[inode] = struct{}{}
		}
	}
	if len(matchingInodes) == 0 {
		return nil, fmt.Sprintf("no Linux socket table entry matches source %s", source), nil
	}

	var owners []int
	for _, pid := range uniqueSortedPositiveInts(candidatePIDs) {
		owned, err := processSocketInodes(pid)
		if err != nil {
			// Candidate processes race with inspection. A disappeared or hidden
			// PID is simply not positive ownership evidence for this snapshot.
			continue
		}
		for inode := range matchingInodes {
			if _, ok := owned[inode]; ok {
				owners = append(owners, pid)
				break
			}
		}
	}
	return owners, fmt.Sprintf("source=%s matched %d kernel socket inode(s) and %d candidate PID(s)", source, len(matchingInodes), len(owners)), nil
}

func splitRuntimeSource(source string) (net.IP, int, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(source))
	if err != nil {
		return nil, 0, fmt.Errorf("parse runtime source %q: %w", source, err)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return nil, 0, fmt.Errorf("runtime source %q does not contain an IP address", source)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return nil, 0, fmt.Errorf("runtime source %q has invalid port", source)
	}
	return ip, port, nil
}

func linuxSocketTables(network string) []string {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "tcp":
		return []string{"/proc/net/tcp", "/proc/net/tcp6"}
	case "udp":
		return []string{"/proc/net/udp", "/proc/net/udp6"}
	case "":
		return []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"}
	default:
		return nil
	}
}

func linuxSourceSocketInodes(path string, expectedIP net.IP, expectedPort int) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]struct{}{}
	s := bufio.NewScanner(f)
	first := true
	for s.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(s.Text())
		if len(fields) < 10 {
			continue
		}
		ip, port, err := decodeProcEndpoint(fields[1])
		if err != nil || port != expectedPort || !ip.Equal(expectedIP) {
			continue
		}
		inode := fields[9]
		if inode != "" && inode != "0" {
			out[inode] = struct{}{}
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
