//go:build !windows

package proxy

import "os"

func hardenSensitiveFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
