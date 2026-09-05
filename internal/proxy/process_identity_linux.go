//go:build linux

package proxy

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// platformProcessIdentity returns Linux's process start time (field 22 of
// /proc/<pid>/stat), which distinguishes a reused PID.
func platformProcessIdentity(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid PID %d", pid)
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", err
	}
	line := string(b)
	closeComm := strings.LastIndex(line, ") ")
	if closeComm < 0 || closeComm+2 >= len(line) {
		return "", fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(line[closeComm+2:])
	// fields[0] is stat field 3; starttime is stat field 22.
	const startTimeIndex = 19
	if len(fields) <= startTimeIndex || fields[0] == "" {
		return "", fmt.Errorf("missing start time in /proc/%d/stat", pid)
	}
	return fields[startTimeIndex], nil
}
