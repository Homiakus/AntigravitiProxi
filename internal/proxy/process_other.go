//go:build !linux

package proxy

import (
	"os"
	"os/exec"
)

func prepareManagedCommand(cmd *exec.Cmd) {}

func stopManagedProcess(p *os.Process) error {
	return p.Kill()
}
