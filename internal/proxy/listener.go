package proxy

import (
	"fmt"
	"net"
	"time"
)

const listenerProbeTimeout = 500 * time.Millisecond

// ManagedPID returns the PID of the sing-box process started by this Manager.
// It intentionally returns 0 for an unmanaged/finished process.
func (m *Manager) ManagedPID() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd == nil || m.cmd.Process == nil {
		return 0
	}
	return m.cmd.Process.Pid
}

// ManagedListenerOwned proves that the configured mixed proxy listener belongs
// to the sing-box process started by this Manager. A successful TCP connect is
// not enough: another process can occupy the configured port and otherwise make
// health look green while the managed data plane is dead.
func (m *Manager) ManagedListenerOwned() (bool, string) {
	pid := m.ManagedPID()
	if pid <= 0 {
		return false, "managed sing-box process is not running"
	}
	cfg := m.Config()
	addr := net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port))
	owned, detail, err := processOwnsTCPListener(pid, cfg.Host, cfg.Port)
	if err != nil {
		return false, err.Error()
	}
	if !owned {
		return false, "configured listener " + addr + " is not owned by managed sing-box: " + detail
	}
	conn, err := net.DialTimeout("tcp", addr, listenerProbeTimeout)
	if err != nil {
		return false, "managed listener ownership found but connect failed: " + err.Error()
	}
	_ = conn.Close()
	return true, detail
}
