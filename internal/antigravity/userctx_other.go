//go:build !linux

package antigravity

import (
	"os"
	"os/exec"
	"path/filepath"
)

func effectiveUserHome() string {
	home, _ := os.UserHomeDir()
	return home
}

func effectiveConfigHome(home string) string {
	if cfg := os.Getenv("XDG_CONFIG_HOME"); cfg != "" {
		return cfg
	}
	return filepath.Join(home, ".config")
}

func prepareLaunchCommand(cmd *exec.Cmd, env []string) ([]string, error) {
	return env, nil
}
