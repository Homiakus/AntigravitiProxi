//go:build !linux

package proxy

import "fmt"

func RunLinuxPrivilegedSetup(binary, expectedSHA256 string) error {
	return fmt.Errorf("Linux privileged setup helper is unavailable on this platform")
}
