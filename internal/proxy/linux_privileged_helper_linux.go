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

// RunLinuxPrivilegedSetup is the narrow internal entry point executed through
// pkexec/sudo. It accepts no arbitrary command. The caller must provide the
// already-verified managed sing-box path and its SHA-256; the helper rechecks
// the digest after privilege elevation before mutating host state.
func RunLinuxPrivilegedSetup(binary, expectedSHA256 string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("privileged Linux setup helper must run as root")
	}
	binary = filepath.Clean(strings.TrimSpace(binary))
	if !filepath.IsAbs(binary) || filepath.Base(binary) != "sing-box" {
		return fmt.Errorf("refusing unexpected managed binary path %q", binary)
	}
	st, err := os.Stat(binary)
	if err != nil {
		return fmt.Errorf("stat managed sing-box: %w", err)
	}
	if st.IsDir() || st.Mode()&0o111 == 0 {
		return fmt.Errorf("managed sing-box is not an executable regular file: %q", binary)
	}

	expectedSHA256 = strings.ToLower(strings.TrimSpace(expectedSHA256))
	if len(expectedSHA256) != 64 {
		return fmt.Errorf("invalid expected sing-box SHA-256")
	}
	actual, err := sha256File(binary)
	if err != nil {
		return fmt.Errorf("hash managed sing-box: %w", err)
	}
	if strings.ToLower(actual) != expectedSHA256 {
		return fmt.Errorf("managed sing-box hash changed before privileged setup: got %s want %s", actual, expectedSHA256)
	}

	if err := privilegedEnsureTunDevice(); err != nil {
		return err
	}
	getcap, setcap, err := privilegedEnsureCapabilityTools()
	if err != nil {
		return err
	}
	if out, err := exec.Command(setcap, linuxTunnelCapabilitySpec, binary).CombinedOutput(); err != nil {
		return fmt.Errorf("setcap managed sing-box: %w: %s", err, strings.TrimSpace(string(out)))
	}
	caps, err := exec.Command(getcap, binary).CombinedOutput()
	if err != nil {
		return fmt.Errorf("verify capabilities: %w", err)
	}
	if missing := missingLinuxCapabilities(string(caps)); len(missing) > 0 {
		return fmt.Errorf("post-setcap verification failed; missing [%s]", strings.Join(missing, ", "))
	}
	return nil
}

func privilegedEnsureTunDevice() error {
	if st, err := os.Stat("/dev/net/tun"); err == nil && !st.IsDir() {
		return nil
	}
	modprobe := findLinuxCommand("modprobe", "/usr/sbin/modprobe", "/sbin/modprobe")
	if modprobe == "" {
		return fmt.Errorf("/dev/net/tun is unavailable and modprobe was not found")
	}
	if out, err := exec.Command(modprobe, "tun").CombinedOutput(); err != nil {
		return fmt.Errorf("modprobe tun: %w: %s", err, strings.TrimSpace(string(out)))
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := os.Stat("/dev/net/tun"); err == nil && !st.IsDir() {
			return nil
		}
		time.Sleep(80 * time.Millisecond)
	}
	return fmt.Errorf("modprobe tun returned successfully but /dev/net/tun did not appear")
}

func privilegedEnsureCapabilityTools() (getcap, setcap string, err error) {
	getcap = findLinuxCommand("getcap", "/usr/sbin/getcap", "/sbin/getcap")
	setcap = findLinuxCommand("setcap", "/usr/sbin/setcap", "/sbin/setcap")
	if getcap != "" && setcap != "" {
		return getcap, setcap, nil
	}

	type installer struct {
		command string
		args    []string
	}
	var candidate *installer
	if p := findLinuxCommand("apt-get", "/usr/bin/apt-get"); p != "" {
		candidate = &installer{p, []string{"install", "-y", "libcap2-bin"}}
	} else if p := findLinuxCommand("dnf", "/usr/bin/dnf"); p != "" {
		candidate = &installer{p, []string{"install", "-y", "libcap"}}
	} else if p := findLinuxCommand("yum", "/usr/bin/yum"); p != "" {
		candidate = &installer{p, []string{"install", "-y", "libcap"}}
	} else if p := findLinuxCommand("pacman", "/usr/bin/pacman"); p != "" {
		candidate = &installer{p, []string{"-S", "--needed", "--noconfirm", "libcap"}}
	} else if p := findLinuxCommand("zypper", "/usr/bin/zypper"); p != "" {
		candidate = &installer{p, []string{"--non-interactive", "install", "libcap-progs"}}
	}
	if candidate == nil {
		return "", "", fmt.Errorf("getcap/setcap are missing and no supported package manager was found")
	}
	cmd := exec.Command(candidate.command, candidate.args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("install capability tools: %w: %s", err, strings.TrimSpace(string(out)))
	}

	getcap = findLinuxCommand("getcap", "/usr/sbin/getcap", "/sbin/getcap")
	setcap = findLinuxCommand("setcap", "/usr/sbin/setcap", "/sbin/setcap")
	if getcap == "" || setcap == "" {
		return "", "", fmt.Errorf("capability tools installation finished but getcap/setcap are unavailable")
	}
	return getcap, setcap, nil
}
