//go:build !linux && !windows

package proxy

import "fmt"

func platformRuntimeConnectionOwners(source, network string, candidatePIDs []int) ([]int, string, error) {
	return nil, "", fmt.Errorf("PID/socket ownership attestation is unsupported on this platform")
}
