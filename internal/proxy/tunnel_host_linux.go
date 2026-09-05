//go:build linux

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var requiredLinuxTunnelCapabilities = []string{
	"cap_net_admin",
	"cap_net_raw",
	"cap_sys_ptrace",
	"cap_dac_read_search",
}

const linuxTunnelCapabilitySpec = "cap_net_admin,cap_net_raw,cap_sys_ptrace,cap_dac_read_search+ep"

// validateAgentTunnelHost is self-healing on desktop Linux. The ordinary-user
// process first checks whether TUN + capabilities are already ready. If not, it
// asks the OS privilege broker to execute this same verified AntigravitiProxi
// binary in a fixed-function internal setup mode. That produces one OS-managed
// authorization flow rather than one prompt per privileged command.
func validateAgentTunnelHost(binary string) error {
	binary = filepath.Clean(strings.TrimSpace(binary))
	if binary == "" || binary == "." {
		return fmt.Errorf("managed sing-box path is empty")
	}

	// Root already has the process-inspection and network privileges required by
	// sing-box. Do not mutate file capability xattrs in privileged CI/netns or in
	// a deliberate root diagnostic launch; only make sure the kernel TUN device
	// exists. Normal desktop operation remains ordinary-user + one-shot broker.
	if os.Geteuid() == 0 {
		return privilegedEnsureTunDevice()
	}
	if linuxTunnelHostReady(binary) {
		return nil
	}

	hash, err := sha256File(binary)
	if err != nil {
		return fmt.Errorf("hash managed sing-box before privilege setup: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve AntigravitiProxi executable for PolicyKit setup: %w", err)
	}
	if err := runLinuxPrivilegeBroker(self, "__linux-privileged-setup", binary, hash); err != nil {
		return fmt.Errorf(
			"automatic Agent Tunnel privilege setup failed: %w; manual fallback: sudo setcap %s %q",
			err, linuxTunnelCapabilitySpec, binary,
		)
	}

	if !linuxTunnelHostReady(binary) {
		return fmt.Errorf("Linux privilege setup returned successfully but TUN/capability readiness could not be proven")
	}
	return nil
}

func linuxTunnelHostReady(binary string) bool {
	if st, err := os.Stat("/dev/net/tun"); err != nil || st.IsDir() {
		return false
	}
	getcap := findLinuxCommand("getcap", "/usr/sbin/getcap", "/sbin/getcap")
	if getcap == "" {
		return false
	}
	caps, err := exec.Command(getcap, binary).CombinedOutput()
	return err == nil && len(missingLinuxCapabilities(string(caps))) == 0
}

func missingLinuxCapabilities(output string) []string {
	// Parse capability clauses, not substrings: names in a filename and
	// permitted-only capabilities do not establish executable readiness.
	present := make(map[string]bool)
	clauses := regexp.MustCompile(`(?:^|\s)((?:cap_[a-z0-9_]+)(?:,cap_[a-z0-9_]+)*)[=+]([eip]+)(?:\s|$)`)
	for _, field := range strings.Fields(strings.ToLower(output)) {
		clause := clauses.FindStringSubmatch(field)
		if clause == nil {
			continue
		}
		if !strings.Contains(clause[2], "e") || !strings.Contains(clause[2], "p") {
			continue
		}
		for _, name := range strings.Split(clause[1], ",") {
			present[name] = true
		}
	}
	missing := make([]string, 0, len(requiredLinuxTunnelCapabilities))
	for _, capName := range requiredLinuxTunnelCapabilities {
		if !present[capName] {
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

// runLinuxPrivilegeBroker never reads or pipes a password. PolicyKit is the
// preferred desktop path. If no graphical authorization agent is usable and
// the parent owns an interactive terminal, sudo may prompt in that terminal.
func runLinuxPrivilegeBroker(command string, args ...string) error {
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

// Preserve explicit gateway host routes outside the chosen VPN. VPN clients
// install these to keep their encrypted transport outside their own tunnel.
func tunnelUpstreamHostRoutes(ctx context.Context, vpn string) ([]string, error) {
	var routes []string
	for _, family := range []string{"-4", "-6"} {
		raw, err := exec.CommandContext(ctx, "ip", "-j", family, "route", "show", "table", "main").Output()
		if err != nil {
			return nil, err
		}
		found, err := parseUpstreamHostRoutes(raw, vpn)
		if err != nil {
			return nil, err
		}
		routes = append(routes, found...)
	}
	return routes, nil
}

func parseUpstreamHostRoutes(raw []byte, vpn string) ([]string, error) {
	var entries []struct {
		Dst     string
		Dev     string
		Gateway string
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	var routes []string
	for _, r := range entries {
		if r.Dev == "" || r.Dev == vpn || r.Dev == agentTunName || r.Gateway == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(r.Dst)
		if err != nil {
			addr, addrErr := netip.ParseAddr(r.Dst)
			if addrErr != nil {
				continue
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		if prefix.Bits() == prefix.Addr().BitLen() {
			routes = append(routes, prefix.String())
		}
	}
	return routes, nil
}
