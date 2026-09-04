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

	// Agent Tunnel does more than create routes. Its core isolation invariant
	// depends on sing-box resolving local sockets back to the owning process so
	// process_name/process_path rules can be authoritative. The upstream
	// sing-box Linux service grants SYS_PTRACE and DAC_READ_SEARCH for exactly
	// this class of process inspection in addition to TUN capabilities.
	//
	// Running the whole desktop control plane as root is avoidable: grant only
	// the capabilities needed by the managed sing-box helper.
	if getcap, err := exec.LookPath("getcap"); err == nil && binary != "" {
		out, _ := exec.Command(getcap, binary).CombinedOutput()
		caps := strings.ToLower(string(out))
		required := []string{
			"cap_net_admin",
			"cap_net_raw",
			"cap_sys_ptrace",
			"cap_dac_read_search",
		}
		var missing []string
		for _, capName := range required {
			if !strings.Contains(caps, capName) {
				missing = append(missing, capName)
			}
		}
		if len(missing) == 0 {
			return nil
		}
		return fmt.Errorf(
			"Agent Tunnel Linux helper is missing capabilities [%s]; grant only the managed sing-box helper what TUN + process attribution require: sudo setcap cap_net_admin,cap_net_raw,cap_sys_ptrace,cap_dac_read_search+ep %q",
			strings.Join(missing, ", "), binary,
		)
	}

	// Some minimal distributions do not ship getcap. Do not claim readiness
	// when the process-attribution invariant cannot be verified. A root launch
	// remains available as a diagnostic fallback, but production setup should
	// install libcap/getcap and use the capability-scoped helper.
	return fmt.Errorf("cannot verify Linux capabilities because getcap is unavailable; install libcap/getcap or run as root for diagnosis, then grant cap_net_admin,cap_net_raw,cap_sys_ptrace,cap_dac_read_search to the managed sing-box helper")
}
