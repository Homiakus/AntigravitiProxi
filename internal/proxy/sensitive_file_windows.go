//go:build windows

package proxy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
)

// Windows FileMode bits are not ACL evidence. Remove inherited permissions
// and grant access only to the interactive account that owns this runtime.
// The command is invoked without a shell and the path is passed as one argv.
func hardenSensitiveFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	current, err := user.Current()
	if err != nil || current.Username == "" {
		return fmt.Errorf("resolve current Windows user: %w", err)
	}
	icacls, err := exec.LookPath("icacls.exe")
	if err != nil {
		return fmt.Errorf("icacls.exe is required for sensitive-file ACL hardening: %w", err)
	}
	if out, err := exec.Command(icacls, path, "/inheritance:r", "/grant:r", current.Username+":F").CombinedOutput(); err != nil {
		return fmt.Errorf("icacls ACL hardening failed: %w: %s", err, out)
	}
	if err := verifySensitiveFileACL(icacls, path, current.Username); err != nil {
		return err
	}
	return nil
}

func verifySensitiveFileACL(icacls, path, username string) error {
	out, err := exec.Command(icacls, path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("read hardened sensitive-file ACL: %w: %s", err, out)
	}
	text := string(out)
	if strings.Contains(text, "(I)") {
		return errors.New("sensitive-file ACL still contains inherited permissions")
	}
	if !strings.Contains(strings.ToLower(text), strings.ToLower(username)) {
		return fmt.Errorf("hardened sensitive-file ACL does not show current user %q: %s", username, text)
	}
	return nil
}
