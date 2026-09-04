//go:build linux

package antigravity

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

func invokingDesktopUser() (*user.User, bool) {
	if os.Geteuid() != 0 {
		return nil, false
	}
	uid := os.Getenv("SUDO_UID")
	if uid == "" {
		uid = os.Getenv("PKEXEC_UID")
	}
	if uid == "" || uid == "0" {
		return nil, false
	}
	u, err := user.LookupId(uid)
	return u, err == nil && u != nil
}

func effectiveUserHome() string {
	if u, ok := invokingDesktopUser(); ok && u.HomeDir != "" {
		return u.HomeDir
	}
	home, _ := os.UserHomeDir()
	return home
}

func effectiveConfigHome(home string) string {
	// An elevated control plane must never edit /root/.config on behalf of the
	// desktop user. For a normal unprivileged launch, honor XDG_CONFIG_HOME.
	if _, ok := invokingDesktopUser(); ok {
		return filepath.Join(home, ".config")
	}
	if cfg := os.Getenv("XDG_CONFIG_HOME"); cfg != "" {
		return cfg
	}
	return filepath.Join(home, ".config")
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		if len(item) >= len(prefix) && item[:len(prefix)] == prefix {
			continue
		}
		out = append(out, item)
	}
	return append(out, prefix+value)
}

// prepareLaunchCommand prevents the common Linux failure mode where the whole
// control plane is started with sudo for TUN permissions and Antigravity is
// consequently launched as root. That creates root-owned IDE state and often
// loses the user's Wayland/DBus/keyring session. When sudo/pkexec identifies
// the invoking user we explicitly drop the child back to that account.
func prepareLaunchCommand(cmd *exec.Cmd, env []string) ([]string, error) {
	if os.Geteuid() != 0 {
		return env, nil
	}
	u, ok := invokingDesktopUser()
	if !ok {
		return nil, errors.New("refusing to launch Antigravity as root: run AntigravitiProxi as the desktop user with sing-box capabilities, or elevate it via sudo/pkexec so the invoking user can be recovered")
	}

	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	gid64, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	groupIDs, _ := u.GroupIds()
	groups := make([]uint32, 0, len(groupIDs))
	for _, raw := range groupIDs {
		g, parseErr := strconv.ParseUint(raw, 10, 32)
		if parseErr == nil {
			groups = append(groups, uint32(g))
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uint32(uid64),
			Gid:    uint32(gid64),
			Groups: groups,
		},
	}

	env = setEnv(env, "HOME", u.HomeDir)
	env = setEnv(env, "USER", u.Username)
	env = setEnv(env, "LOGNAME", u.Username)
	env = setEnv(env, "XDG_CONFIG_HOME", filepath.Join(u.HomeDir, ".config"))
	env = setEnv(env, "XDG_CACHE_HOME", filepath.Join(u.HomeDir, ".cache"))

	runtimeDir := filepath.Join("/run/user", u.Uid)
	if st, statErr := os.Stat(runtimeDir); statErr == nil && st.IsDir() {
		env = setEnv(env, "XDG_RUNTIME_DIR", runtimeDir)
		bus := filepath.Join(runtimeDir, "bus")
		if _, statErr = os.Stat(bus); statErr == nil {
			env = setEnv(env, "DBUS_SESSION_BUS_ADDRESS", "unix:path="+bus)
		}
	}
	return env, nil
}
