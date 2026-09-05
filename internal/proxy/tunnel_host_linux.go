//go:build linux

package proxy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var requiredLinuxTunnelCapabilities = []string{
	"cap_net_admin",
	"cap_net_raw",
	"cap_sys_ptrace",
	"cap_dac_read_search",
}

const linuxTunnelCapabilitySpec = "cap_net_admin,cap_net_raw,cap_sys_ptrace,cap_dac_read_search+ep"

// validateAgentTunnelHost is deliberately self-healing on desktop Linux.
// Starting Agent Tunnel is an explicit privileged operation, so the program may
// ask the OS authentication agent (PolicyKit) to load TUN and grant the managed
// sing-box binary the narrow capabilities it needs. The Go control plane and
// Antigravity IDE remain unprivileged.
func validateAgentTunnelHost(binary string) error {
	if strings.TrimSpace(binary) == "" {
		return fmt.Errorf("managed sing-box path is empty")
	}
	if err := ensureLinuxTunDevice(); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return nil
	}

	getcap, setcap, err := ensureLinuxCapabilityTools()
	if err != nil {
		return err
	}
	caps, _ := exec.Command(getcap, binary).CombinedOutput()
	if missing := missingLinuxCapabilities(string(caps)); len(missing) == 0 {
		return nil
	}

	if err := runLinuxElevated(setcap, linuxTunnelCapabilitySpec, binary); err != nil {
		return fmt.Errorf(
			"automatic Agent Tunnel privilege setup failed: %w; you can retry after running: sudo setcap %s %q",
			err, linuxTunnelCapabilitySpec, binary,
		)
	}

	caps, err = exec.Command(getcap, binary).CombinedOutput()
	if err != nil {
		return fmt.Errorf("verify Linux capabilities after elevation: %w", err)
	}
	if missing := missingLinuxCapabilities(string(caps)); len(missing) > 0 {
		return fmt.Errorf("Linux privilege setup completed but required capabilities are still missing [%s] on %q", strings.Join(missing, ", "), binary)
	}
	return nil
}

func ensureLinuxTunDevice() error {
	if st, err := os.Stat("/dev/net/tun"); err == nil && !st.IsDir() {
		return nil
	}

	modprobe := findLinuxCommand("modprobe", "/usr/sbin/modprobe", "/sbin/modprobe")
	if modprobe == "" {
		return fmt.Errorf("Linux TUN device /dev/net/tun is unavailable and modprobe was not found")
	}
	if err := runLinuxElevated(modprobe, "tun"); err != nil {
		return fmt.Errorf("cannot load Linux TUN module automatically: %w", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := os.Stat("/dev/net/tun"); err == nil && !st.IsDir() {
			return nil
		}
		time.Sleep(80 * time.Millisecond)
	}
	return fmt.Errorf("TUN module was requested successfully but /dev/net/tun did not appear")
}

func ensureLinuxCapabilityTools() (getcap, setcap string, err error) {
	getcap = findLinuxCommand("getcap", "/usr/sbin/getcap", "/sbin/getcap")
	setcap = findLinuxCommand("setcap", "/usr/sbin/setcap", "/sbin/setcap")
	if getcap != "" && setcap != "" {
		return getcap, setcap, nil
	}

	// Keep package installation bounded to the capability tooling only. This is
	// reached only after the user explicitly starts Agent Tunnel.
	type installer struct {
		command string
		args    []string
	}
	var candidates []installer
	if p := findLinuxCommand("apt-get", "/usr/bin/apt-get"); p != "" {
		candidates = append(candidates, installer{p, []string{"install", "-y", "libcap2-bin"}})
	}
	if p := findLinuxCommand("dnf", "/usr/bin/dnf"); p != "" {
		candidates = append(candidates, installer{p, []string{"install", "-y", "libcap"}})
	}
	if p := findLinuxCommand("yum", "/usr/bin/yum"); p != "" {
		candidates = append(candidates, installer{p, []string{"install", "-y", "libcap"}})
	}
	if p := findLinuxCommand("pacman", "/usr/bin/pacman"); p != "" {
		candidates = append(candidates, installer{p, []string{"-S", "--needed", "--noconfirm", "libcap"}})
	}
	if p := findLinuxCommand("zypper", "/usr/bin/zypper"); p != "" {
		candidates = append(candidates, installer{p, []string{"--non-interactive", "install", "libcap-progs"}})
	}
	if len(candidates) == 0 {
		return "", "", fmt.Errorf("getcap/setcap are missing and no supported package manager was found; install libcap tools for your distribution")
	}
	if err := runLinuxElevated(candidates[0].command, candidates[0].args...); err != nil {
		return "", "", fmt.Errorf("install Linux capability tools automatically: %w", err)
	}

	getcap = findLinuxCommand("getcap", "/usr/sbin/getcap", "/sbin/getcap")
	setcap = findLinuxCommand("setcap", "/usr/sbin/setcap", "/sbin/setcap")
	if getcap == "" || setcap == "" {
		return "", "", fmt.Errorf("capability tools installation finished but getcap/setcap are still unavailable")
	}
	return getcap, setcap, nil
}

func missingLinuxCapabilities(output string) []string {
	caps := strings.ToLower(output)
	missing := make([]string, 0, len(requiredLinuxTunnelCapabilities))
	for _, capName := range requiredLinuxTunnelCapabilities {
		if !strings.Contains(caps, capName) {
			missing = append(missing, capName)
		}
	}
	return missing
}

func findLinuxCommand(name string, absolute ...string) string {
	if p, err := exec.LookPath(name); err == nil {
		if q, err := filepath.Abs(p); err == nil {
			return q
		}
		return p
	}
	for _, p := range absolute {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// runLinuxElevated never handles or stores a password. On a desktop it prefers
// PolicyKit, which displays the distro-native authentication dialog. If no
// PolicyKit agent is available and AntigravitiProxi owns a terminal, sudo is
// allowed to prompt in that existing terminal as a fallback.
func runLinuxElevated(command string, args ...string) error {
	if os.Geteuid() == 0 {
		cmd := exec.Command(command, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %w: %s", filepath.Base(command), err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	var pkexecErr error
	if pkexec := findLinuxCommand("pkexec", "/usr/bin/pkexec"); pkexec != "" {
		argv := append([]string{command}, args...)
		cmd := exec.Command(pkexec, argv...)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		pkexecErr = fmt.Errorf("PolicyKit authorization failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	if sudo := findLinuxCommand("sudo", "/usr/bin/sudo", "/bin/sudo"); sudo != "" && stdinIsTerminal() {
		argv := append([]string{"--", command}, args...)
		cmd := exec.Command(sudo, argv...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err == nil {
			return nil
		} else if pkexecErr == nil {
			return fmt.Errorf("sudo authorization failed: %w", err)
		}
	}
	if pkexecErr != nil {
		return pkexecErr
	}
	return fmt.Errorf("no usable privilege broker found: install PolicyKit/pkexec or launch AntigravitiProxi from a terminal with sudo available")
}

func stdinIsTerminal() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
