//go:build linux

package antigravity

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func listPlatformProcesses() ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := make([]ProcessInfo, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		p, err := readLinuxProcess(pid)
		if err != nil {
			// Processes race with enumeration and permissions can hide unrelated
			// system tasks. Skip an individual unreadable PID rather than making
			// the entire Antigravity inventory unusable.
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func readLinuxProcess(pid int) (ProcessInfo, error) {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	f, err := os.Open(filepath.Join(base, "status"))
	if err != nil {
		return ProcessInfo{}, err
	}
	defer f.Close()

	p := ProcessInfo{PID: pid}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		switch {
		case strings.HasPrefix(line, "Name:"):
			p.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "PPid:"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
			p.PPID, _ = strconv.Atoi(v)
		}
	}
	if err := s.Err(); err != nil {
		return ProcessInfo{}, err
	}
	if p.Name == "" {
		return ProcessInfo{}, fmt.Errorf("pid %d has no Name in status", pid)
	}
	if exe, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		p.Executable = exe
	}
	if raw, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
		parts := strings.Split(string(raw), "\x00")
		clean := parts[:0]
		for _, part := range parts {
			if part != "" {
				clean = append(clean, part)
			}
		p.CommandLine = strings.Join(clean, " ")
	}
	return p, nil
}
