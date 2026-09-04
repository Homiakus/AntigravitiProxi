//go:build linux

package proxy

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func validateAgentTunnelHost(binary string) error {
	if st, err := os.Stat("/dev/net/tun"); err != nil || st.IsDir() {
		return fmt.Errorf("Linux TUN device /dev/net/tun is unavailable; load the tun module (for example: sudo modprobe tun) before starting Agent Tunnel")
	}
	if os.Geteuid() == 0 {
		return nil
	}

	// Running the whole desktop control plane as root is avoidable. A safer
	// Linux setup grants only the network capabilities needed by sing-box.
	if getcap, err := exec.LookPath("getcap"); err == nil && binary != "" {
		out, _ := exec.Command(getcap, binary).CombinedOutput()
		caps := strings.ToLower(string(out))
		hasAdmin := strings.Contains(caps, "cap_net_admin")
		hasRaw := strings.Contains(caps, "cap_net_raw")
		if hasAdmin && hasRaw {
			return nil
		}
		return fmt.Errorf("Agent Tunnel needs CAP_NET_ADMIN and CAP_NET_RAW on Linux; grant them only to sing-box instead of running the IDE as root: sudo setcap cap_net_admin,cap_net_raw+ep %q", binary)
	}

	// Some minimal distributions do not ship getcap. Do not reject a binary
	// whose file capabilities we cannot inspect; sing-box startup will still be
	// authoritative and the caller appends the privilege hint to any failure.
	return nil
}
