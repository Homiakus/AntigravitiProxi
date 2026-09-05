//go:build !linux

package proxy

import (
	"context"
	"errors"
)

type linuxHardLaunchState struct {
	Namespace string
	HostVeth  string
	PeerVeth  string
	VPN       string
	UID       uint32
	PID       int
	Cgroup    string
}

func (m *Manager) KernelHardAvailable() error {
	return errors.New("kernel-hard isolation is supported only on Linux")
}
func (m *Manager) KernelHardPreflight(context.Context) error {
	return errors.New("kernel-hard isolation is supported only on Linux")
}
func (m *Manager) KernelHardState() (linuxHardLaunchState, error) {
	return linuxHardLaunchState{}, errors.New("kernel-hard isolation is supported only on Linux")
}
func (m *Manager) KernelHardStateActive() bool    { return false }
func (m *Manager) KernelHardProcessRunning() bool { return false }
func (m *Manager) LaunchKernelHard(string, []string) error {
	return errors.New("kernel-hard isolation is supported only on Linux")
}
func RunLinuxHardLaunch(string, string, string, string, uint32) error {
	return errors.New("kernel-hard isolation is supported only on Linux")
}
func RunLinuxHardChild(string, string, uint32) error {
	return errors.New("kernel-hard isolation is supported only on Linux")
}
