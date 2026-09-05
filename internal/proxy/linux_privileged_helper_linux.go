//go:build linux

package proxy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// RunLinuxPrivilegedSetup is the narrow internal entry point executed through
// pkexec/sudo. It accepts no arbitrary command. The caller must provide the
// already-verified managed sing-box path and its SHA-256; the helper rechecks
// identity and digest after privilege elevation before mutating host state.
func RunLinuxPrivilegedSetup(binary, expectedSHA256 string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("privileged Linux setup helper must run as root")
	}
	binary = filepath.Clean(strings.TrimSpace(binary))
	if err := validatePrivilegedManagedBinaryTarget(binary); err != nil {
		return err
	}

	expectedSHA256 = strings.ToLower(strings.TrimSpace(expectedSHA256))
	if len(expectedSHA256) != 64 {
		return fmt.Errorf("invalid expected sing-box SHA-256")
	}
	if err := verifyExpectedBinaryHash(binary, expectedSHA256); err != nil {
		return err
	}

	if err := privilegedEnsureTunDevice(); err != nil {
		return err
	}
	getcap, setcap, err := privilegedEnsureCapabilityTools()
	if err != nil {
		return err
	}

	// Package installation/modprobe can take time. Recheck immediately before
	// granting capabilities so a same-user replacement cannot reuse the earlier
	// digest check. This is intentionally fail-closed.
	if err := validatePrivilegedManagedBinaryTarget(binary); err != nil {
		return err
	}
	if err := verifyExpectedBinaryHash(binary, expectedSHA256); err != nil {
		return err
	}
	if out, err := exec.Command(setcap, linuxTunnelCapabilitySpec, binary).CombinedOutput(); err != nil {
		return fmt.Errorf("setcap managed sing-box: %w: %s", err, strings.TrimSpace(string(out)))
	}

	// Verify content again after setcap. File capabilities only change xattrs, so
	// the content digest must remain identical. If a race replaced the file,
	// revoke capabilities immediately and fail.
	if err := verifyExpectedBinaryHash(binary, expectedSHA256); err != nil {
		_, _ = exec.Command(setcap, "-r", binary).CombinedOutput()
		return fmt.Errorf("managed binary changed during capability grant; capabilities revoked: %w", err)
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

func validatePrivilegedManagedBinaryTarget(binary string) error {
	if !filepath.IsAbs(binary) || filepath.Base(binary) != "sing-box" {
		return fmt.Errorf("refusing unexpected managed binary path %q", binary)
	}
	parent := filepath.Dir(binary)
	if filepath.Base(parent) != "bin" || filepath.Base(filepath.Dir(parent)) != "AntigravitiProxi" {
		return fmt.Errorf("refusing binary outside AntigravitiProxi/bin ownership boundary: %q", binary)
	}
	lst, err := os.Lstat(binary)
	if err != nil {
		return fmt.Errorf("lstat managed sing-box: %w", err)
	}
	if lst.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink as privileged managed sing-box target: %q", binary)
	}
	if !lst.Mode().IsRegular() || lst.Mode()&0o111 == 0 {
		return fmt.Errorf("managed sing-box is not an executable regular file: %q", binary)
	}

	uid, haveInvoker, err := invokingDesktopUID()
	if err != nil {
		return err
	}
	if haveInvoker {
		stat, ok := lst.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot verify managed sing-box owner")
		}
		if stat.Uid != uid {
			return fmt.Errorf("refusing capability grant: managed sing-box owner uid=%d does not match invoking desktop uid=%d", stat.Uid, uid)
		}
		if pst, err := os.Stat(parent); err != nil {
			return fmt.Errorf("stat managed bin directory: %w", err)
		} else if ps, ok := pst.Sys().(*syscall.Stat_t); !ok || ps.Uid != uid {
			return fmt.Errorf("refusing capability grant: managed bin directory is not owned by invoking desktop uid=%d", uid)
		}
	}
	return nil
}

func invokingDesktopUID() (uint32, bool, error) {
	for _, key := range []string{"PKEXEC_UID", "SUDO_UID"} {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			continue
		}
		v, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return 0, false, fmt.Errorf("invalid %s=%q", key, raw)
		}
		return uint32(v), true, nil
	}
	return 0, false, nil
}

func verifyExpectedBinaryHash(binary, expected string) error {
	actual, err := sha256File(binary)
	if err != nil {
		return fmt.Errorf("hash managed sing-box: %w", err)
	}
	if strings.ToLower(actual) != expected {
		return fmt.Errorf("managed sing-box hash changed before privileged setup: got %s want %s", actual, expected)
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
