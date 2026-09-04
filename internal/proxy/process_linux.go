//go:build linux

package proxy

import (
	"os"
	"os/exec"
	"syscall"
)

// prepareManagedCommand makes the network helper die if the Go control plane
// disappears unexpectedly. Without Pdeathsig an orphaned sing-box can keep a
// TUN interface, policy routes and nftables state alive after the UI process
// has crashed or been killed.
func prepareManagedCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}

// stopManagedProcess gives sing-box a chance to remove TUN routes/nftables
// state cleanly. StopAndWait retains a SIGKILL fallback for a stuck helper.
func stopManagedProcess(p *os.Process) error {
	return p.Signal(syscall.SIGTERM)
}
