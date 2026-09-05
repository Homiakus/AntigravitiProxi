//go:build linux

package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	hardNamespacePrefix = "agp-net-"
	hardHostVethPrefix  = "agp-h-"
	hardPeerVethPrefix  = "agp-n-"
	hardTableBase       = 20240
	hardRuleBase        = 19240
	hardV4Prefix        = "198.18.0.0/30"
	hardV6Host          = "fd42:aa:1::1/126"
	hardV6Peer          = "fd42:aa:1::2/126"
)

type linuxHardLaunchState struct {
	Namespace   string `json:"namespace"`
	HostVeth    string `json:"host_veth"`
	PeerVeth    string `json:"peer_veth"`
	VPN         string `json:"vpn_interface"`
	UID         uint32 `json:"uid"`
	PID         int    `json:"pid,omitempty"`
	Cgroup      string `json:"cgroup"`
	Forward4    string `json:"forwarding_ipv4,omitempty"`
	Forward6    string `json:"forwarding_ipv6,omitempty"`
	ForwardAll4 string `json:"forwarding_all_ipv4,omitempty"`
	ForwardAll6 string `json:"forwarding_all_ipv6,omitempty"`
	ForwardVPN4 string `json:"forwarding_vpn_ipv4,omitempty"`
	ForwardVPN6 string `json:"forwarding_vpn_ipv6,omitempty"`
}

type hardTransportRoutes struct {
	IPv4 []string
	IPv6 []string
}

func hardNames(uid uint32) (string, string, string) {
	s := strconv.FormatUint(uint64(uid), 10)
	return hardNamespacePrefix + s, hardHostVethPrefix + s, hardPeerVethPrefix + s
}

func hardCgroupPath(uid uint32) string {
	return filepath.Join("/sys/fs/cgroup", "antigraviti-proxi-"+strconv.FormatUint(uint64(uid), 10))
}

func linuxHardStatePath(root string) string { return filepath.Join(root, "kernel-hard-state.json") }

func writeHardState(root string, state linuxHardLaunchState) error {
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(linuxHardStatePath(root), append(b, '\n'), 0o600)
}

func readHardState(root string) (linuxHardLaunchState, error) {
	b, err := os.ReadFile(linuxHardStatePath(root))
	if err != nil {
		return linuxHardLaunchState{}, err
	}
	var state linuxHardLaunchState
	if err := json.Unmarshal(b, &state); err != nil {
		return state, err
	}
	if state.Namespace == "" || state.HostVeth == "" || state.PeerVeth == "" || state.VPN == "" {
		return state, errors.New("invalid kernel-hard state")
	}
	return state, nil
}

func LinuxHardIsolationAvailable() error {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return fmt.Errorf("cgroup v2 unavailable: %w", err)
	}
	for _, name := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(name); err != nil {
			return fmt.Errorf("required Linux command %q is unavailable: %w", name, err)
		}
	}
	return nil
}

func RunLinuxHardLaunch(root, vpn, executable, envPath string, uid uint32) error {
	if os.Geteuid() != 0 {
		return errors.New("kernel-hard launch helper must run as root")
	}
	if err := validateHardTarget(root, executable, envPath, uid); err != nil {
		return err
	}
	if strings.TrimSpace(vpn) == "" || vpn == agentTunName {
		return fmt.Errorf("invalid kernel-hard VPN interface %q", vpn)
	}
	if !safeLinuxName(vpn) {
		return fmt.Errorf("invalid VPN interface name %q", vpn)
	}
	if _, err := netInterface(vpn); err != nil {
		return err
	}
	ns, hostVeth, peerVeth := hardNames(uid)
	state := linuxHardLaunchState{Namespace: ns, HostVeth: hostVeth, PeerVeth: peerVeth, VPN: vpn, UID: uid, Cgroup: hardCgroupPath(uid)}
	if err := captureForwarding(&state); err != nil {
		return err
	}
	if err := hardSetup(root, state); err != nil {
		return err
	}
	defer hardCleanup(state)
	defer os.Remove(linuxHardStatePath(root))
	defer os.Remove(envPath)
	parentCgroup, err := currentCgroupPath()
	if err != nil {
		return err
	}
	if err := moveSelfToCgroup(state.Cgroup); err != nil {
		return err
	}
	defer func() { _ = moveSelfToCgroup(parentCgroup) }()

	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command("ip", "netns", "exec", ns, self, "__linux-hard-child", executable, envPath, strconv.FormatUint(uint64(uid), 10))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start Antigravity in kernel namespace: %w", err)
	}
	state.PID = cmd.Process.Pid
	_ = writeHardState(root, state)
	err = cmd.Wait()
	_ = writeHardRuntimeEvidence(root, state)
	if err != nil {
		return fmt.Errorf("protected Antigravity exited: %w", err)
	}
	return nil
}

func writeHardRuntimeEvidence(root string, state linuxHardLaunchState) error {
	var b strings.Builder
	for _, item := range []struct {
		name string
		cmd  []string
	}{
		{"rules4", []string{"ip", "-4", "rule", "show"}},
		{"routes4", []string{"ip", "-4", "route", "show", "table", strconv.Itoa(hardTableBase)}},
		{"rules6", []string{"ip", "-6", "rule", "show"}},
		{"routes6", []string{"ip", "-6", "route", "show", "table", strconv.Itoa(hardTableBase)}},
		{"nft", []string{"nft", "list", "table", "inet", "agp_hard_" + strconv.FormatUint(uint64(state.UID), 10)}},
		{"iptables4", []string{"iptables", "-S", "FORWARD"}},
		{"iptables6", []string{"ip6tables", "-S", "FORWARD"}},
	} {
		out, err := exec.Command(item.cmd[0], item.cmd[1:]...).CombinedOutput()
		b.WriteString("=== ")
		b.WriteString(item.name)
		b.WriteString(" ===\n")
		b.Write(out)
		if err != nil {
			b.WriteString("error: ")
			b.WriteString(err.Error())
			b.WriteByte('\n')
		}
	}
	path := filepath.Join(root, "kernel-hard-last-evidence.txt")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return err
	}
	_ = os.Chown(path, int(state.UID), -1)
	return nil
}

func RunLinuxHardChild(executable, envPath string, uid uint32) error {
	envRaw, err := os.ReadFile(envPath)
	if err != nil {
		return fmt.Errorf("read protected launch environment: %w", err)
	}
	var env []string
	if err := json.Unmarshal(envRaw, &env); err != nil {
		return fmt.Errorf("decode protected launch environment: %w", err)
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return err
	}
	uid64, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid64, _ := strconv.ParseUint(u.Gid, 10, 32)
	cmd := exec.Command(executable)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid64), Gid: uint32(gid64)}}
	return cmd.Run()
}

func validateHardTarget(root, executable, envPath string, uid uint32) error {
	root, _ = filepath.Abs(root)
	if !filepath.IsAbs(executable) || filepath.Base(executable) == "" {
		return fmt.Errorf("refusing non-absolute Antigravity executable %q", executable)
	}
	if filepath.Clean(envPath) != filepath.Join(root, "kernel-hard-env.json") {
		return fmt.Errorf("refusing environment file outside AntigravitiProxi root")
	}
	st, err := os.Stat(executable)
	if err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
		return fmt.Errorf("invalid Antigravity executable: %w", err)
	}
	if st, err = os.Stat(envPath); err != nil || st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("protected launch environment must be a private regular file: %w", err)
	}
	if stat, ok := st.Sys().(*syscall.Stat_t); !ok || stat.Uid != uid {
		return errors.New("protected launch environment is not owned by the invoking desktop user")
	}
	if _, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err != nil {
		return fmt.Errorf("invalid protected launch uid: %w", err)
	}
	return nil
}

func hardSetup(root string, state linuxHardLaunchState) error {
	cleanup := func() { hardCleanup(state) }
	run := func(args ...string) error {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := run("netns", "add", state.Namespace); err != nil {
		return err
	}
	if err := hardOwnershipFree(state); err != nil {
		cleanup()
		return err
	}
	if err := os.Mkdir(state.Cgroup, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		cleanup()
		return fmt.Errorf("create protected cgroup: %w", err)
	}
	if err := setForwarding(true); err != nil {
		cleanup()
		return err
	}
	if err := setForwarding6(true); err != nil {
		cleanup()
		return err
	}
	if err := enableInterfaceForwarding(state.VPN); err != nil {
		cleanup()
		return err
	}
	if err := run("link", "add", state.HostVeth, "type", "veth", "peer", "name", state.PeerVeth); err != nil {
		cleanup()
		return err
	}
	if err := run("link", "set", state.PeerVeth, "netns", state.Namespace); err != nil {
		cleanup()
		return err
	}
	for _, args := range [][]string{
		{"addr", "add", "198.18.0.1/30", "dev", state.HostVeth},
		{"-6", "addr", "add", hardV6Host, "dev", state.HostVeth},
		{"link", "set", state.HostVeth, "up"},
		{"-n", state.Namespace, "link", "set", "lo", "up"},
		{"-n", state.Namespace, "addr", "add", "198.18.0.2/30", "dev", state.PeerVeth},
		{"-n", state.Namespace, "-6", "addr", "add", hardV6Peer, "dev", state.PeerVeth},
		{"-n", state.Namespace, "link", "set", state.PeerVeth, "up"},
		{"-n", state.Namespace, "route", "replace", "default", "via", "198.18.0.1"},
		{"-n", state.Namespace, "-6", "route", "replace", "default", "via", "fd42:aa:1::1"},
	} {
		if err := run(args...); err != nil {
			cleanup()
			return err
		}
	}
	if err := disableVethReversePathFilter(state.HostVeth); err != nil {
		cleanup()
		return err
	}
	transport, err := installHardRoutes(run, state)
	if err != nil {
		cleanup()
		return err
	}
	if err := installHardFirewall(state, transport); err != nil {
		cleanup()
		return err
	}
	resolvDir := filepath.Join("/etc/netns", state.Namespace)
	if err := os.MkdirAll(resolvDir, 0o755); err != nil {
		cleanup()
		return err
	}
	if err := os.WriteFile(filepath.Join(resolvDir, "resolv.conf"), []byte("nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 2606:4700:4700::1111\n"), 0o644); err != nil {
		cleanup()
		return err
	}
	if err := writeHardState(root, state); err != nil {
		cleanup()
		return err
	}
	if err := os.Chown(linuxHardStatePath(root), int(state.UID), -1); err != nil {
		cleanup()
		return fmt.Errorf("handoff kernel-hard state ownership: %w", err)
	}
	if err := os.Chmod(linuxHardStatePath(root), 0o644); err != nil {
		cleanup()
		return err
	}
	return nil
}

func disableVethReversePathFilter(veth string) error {
	path := filepath.Join("/proc/sys/net/ipv4/conf", veth, "rp_filter")
	if err := os.WriteFile(path, []byte("0"), 0o644); err != nil {
		return fmt.Errorf("disable strict rp_filter on protected veth %q: %w", veth, err)
	}
	return nil
}

func installHardRoutes(run func(...string) error, state linuxHardLaunchState) (hardTransportRoutes, error) {
	// The dedicated table is intentionally selected only for packets entering
	// from the protected veth. The host's ordinary routing remains untouched.
	v4src := interfaceSourceAddress(state.VPN, "-4")
	v6src := interfaceSourceAddress(state.VPN, "-6")
	routes := [][]string{
		{"-4", "rule", "add", "priority", strconv.Itoa(hardRuleBase), "from", "198.18.0.2/32", "table", strconv.Itoa(hardTableBase)},
		{"-6", "rule", "add", "priority", strconv.Itoa(hardRuleBase), "from", "fd42:aa:1::2/128", "table", strconv.Itoa(hardTableBase)},
		{"-4", "route", "replace", "default", "dev", state.VPN},
		{"-6", "route", "replace", "default", "dev", state.VPN},
	}
	if v4src != "" {
		routes[2] = append(routes[2], "src", v4src)
	}
	if v6src != "" {
		routes[3] = append(routes[3], "src", v6src)
	}
	routes[2] = append(routes[2], "table", strconv.Itoa(hardTableBase))
	routes[3] = append(routes[3], "table", strconv.Itoa(hardTableBase))
	for _, args := range routes {
		if err := run(args...); err != nil {
			return hardTransportRoutes{}, err
		}
	}
	transport, err := copyHostTransportRoutes(run, state)
	return transport, err
}

func interfaceSourceAddress(vpn, family string) string {
	raw, err := exec.Command("ip", "-j", family, "addr", "show", "dev", vpn).Output()
	if err != nil {
		return ""
	}
	var rows []struct {
		AddrInfo []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(raw, &rows) != nil || len(rows) == 0 {
		return ""
	}
	for _, info := range rows[0].AddrInfo {
		if info.Local != "" {
			return info.Local
		}
	}
	return ""
}

func copyHostTransportRoutes(run func(...string) error, state linuxHardLaunchState) (hardTransportRoutes, error) {
	var out hardTransportRoutes
	for _, family := range []string{"-4", "-6"} {
		raw, err := exec.Command("ip", "-j", family, "route", "show", "table", "main").Output()
		if err != nil {
			return out, fmt.Errorf("inspect host transport routes: %w", err)
		}
		var routes []struct {
			Dst     string `json:"dst"`
			Dev     string `json:"dev"`
			Gateway string `json:"gateway"`
		}
		if err := json.Unmarshal(raw, &routes); err != nil {
			return out, err
		}
		for _, route := range routes {
			if route.Dev == "" || route.Dev == state.VPN || route.Dst == "default" {
				continue
			}
			prefix, err := netip.ParsePrefix(route.Dst)
			if err != nil {
				addr, addrErr := netip.ParseAddr(route.Dst)
				if addrErr != nil {
					continue
				}
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			if prefix.Bits() != prefix.Addr().BitLen() || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() {
				continue
			}
			args := []string{family, "route", "replace", prefix.String()}
			if route.Gateway != "" {
				args = append(args, "via", route.Gateway)
			}
			args = append(args, "dev", route.Dev, "table", strconv.Itoa(hardTableBase))
			if err := run(args...); err != nil {
				return out, err
			}
			if prefix.Addr().Is4() {
				out.IPv4 = append(out.IPv4, prefix.Addr().String())
			} else {
				out.IPv6 = append(out.IPv6, prefix.Addr().String())
			}
		}
	}
	return out, nil
}

func installHardFirewall(state linuxHardLaunchState, transport hardTransportRoutes) error {
	table := "agp_hard_" + strconv.FormatUint(uint64(state.UID), 10)
	script := fmt.Sprintf("add table inet %s\n", table)
	if len(transport.IPv4) > 0 {
		script += fmt.Sprintf("add set inet %s transport4 { type ipv4_addr; elements = { %s } }\n", table, strings.Join(transport.IPv4, ", "))
	}
	if len(transport.IPv6) > 0 {
		script += fmt.Sprintf("add set inet %s transport6 { type ipv6_addr; elements = { %s } }\n", table, strings.Join(transport.IPv6, ", "))
	}
	script += fmt.Sprintf("add chain inet %s forward { type filter hook forward priority -150; policy accept; }\n", table)
	script += fmt.Sprintf("add chain inet %s postrouting { type nat hook postrouting priority 100; policy accept; }\n", table)
	script += fmt.Sprintf("add rule inet %s postrouting oifname \"%s\" ip saddr %s counter masquerade\n", table, state.VPN, hardV4Prefix)
	script += fmt.Sprintf("add rule inet %s postrouting oifname \"%s\" ip6 saddr fd42:aa:1::/126 counter masquerade\n", table, state.VPN)
	script += fmt.Sprintf("add rule inet %s forward ct state established,related oifname \"%s\" counter accept\n", table, state.HostVeth)
	if len(transport.IPv4) > 0 {
		script += fmt.Sprintf("add rule inet %s forward iifname \"%s\" ip daddr @transport4 counter accept\n", table, state.HostVeth)
	}
	if len(transport.IPv6) > 0 {
		script += fmt.Sprintf("add rule inet %s forward iifname \"%s\" ip6 daddr @transport6 counter accept\n", table, state.HostVeth)
	}
	script += fmt.Sprintf("add rule inet %s forward iifname \"%s\" oifname \"%s\" counter accept\n", table, state.HostVeth, state.VPN)
	script += fmt.Sprintf("add rule inet %s forward iifname \"%s\" counter drop\n", table, state.HostVeth)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("install kernel kill-switch: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func hardOwnershipFree(state linuxHardLaunchState) error {
	if _, err := exec.Command("ip", "link", "show", "dev", state.HostVeth).Output(); err == nil {
		return fmt.Errorf("kernel-hard host veth %q already exists", state.HostVeth)
	}
	if _, err := exec.Command("nft", "list", "table", "inet", "agp_hard_"+strconv.FormatUint(uint64(state.UID), 10)).Output(); err == nil {
		return errors.New("kernel-hard nftables table already exists")
	}
	for _, family := range []string{"-4", "-6"} {
		if out, err := exec.Command("ip", family, "rule", "show").Output(); err == nil && strings.Contains(string(out), strconv.Itoa(hardRuleBase)+":") {
			return fmt.Errorf("kernel-hard policy priority %d is already in use", hardRuleBase)
		}
	}
	if _, err := os.Stat(state.Cgroup); err == nil {
		return fmt.Errorf("kernel-hard cgroup %q already exists", state.Cgroup)
	}
	return nil
}

func safeLinuxName(name string) bool {
	if len(name) == 0 || len(name) > 15 {
		return false
	}
	for _, r := range name {
		if !(r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

func hardCleanup(state linuxHardLaunchState) {
	table := "agp_hard_" + strconv.FormatUint(uint64(state.UID), 10)
	_, _ = exec.Command("nft", "delete", "table", "inet", table).CombinedOutput()
	for _, args := range [][]string{
		{"-4", "rule", "del", "priority", strconv.Itoa(hardRuleBase), "from", "198.18.0.2/32", "table", strconv.Itoa(hardTableBase)},
		{"-6", "rule", "del", "priority", strconv.Itoa(hardRuleBase), "from", "fd42:aa:1::2/128", "table", strconv.Itoa(hardTableBase)},
		{"-4", "route", "flush", "table", strconv.Itoa(hardTableBase)},
		{"-6", "route", "flush", "table", strconv.Itoa(hardTableBase)},
		{"link", "del", state.HostVeth},
		{"netns", "del", state.Namespace},
	} {
		_, _ = exec.Command("ip", args...).CombinedOutput()
	}
	_ = os.RemoveAll(filepath.Join("/etc/netns", state.Namespace))
	if state.Forward4 != "" {
		_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(state.Forward4), 0o644)
	}
	if state.Forward6 != "" {
		_ = os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte(state.Forward6), 0o644)
	}
	restoreForwarding(state)
	_ = os.Remove(state.Cgroup)
}

func captureForwarding(state *linuxHardLaunchState) error {
	v4, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return fmt.Errorf("read IPv4 forwarding state: %w", err)
	}
	v6, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
	if err != nil {
		return fmt.Errorf("read IPv6 forwarding state: %w", err)
	}
	state.Forward4 = strings.TrimSpace(string(v4))
	state.Forward6 = strings.TrimSpace(string(v6))
	for _, item := range []struct {
		path *string
		file string
	}{
		{&state.ForwardAll4, "/proc/sys/net/ipv4/conf/all/forwarding"},
		{&state.ForwardAll6, "/proc/sys/net/ipv6/conf/all/forwarding"},
		{&state.ForwardVPN4, filepath.Join("/proc/sys/net/ipv4/conf", state.VPN, "forwarding")},
		{&state.ForwardVPN6, filepath.Join("/proc/sys/net/ipv6/conf", state.VPN, "forwarding")},
	} {
		b, err := os.ReadFile(item.file)
		if err != nil {
			return fmt.Errorf("read forwarding state %s: %w", item.file, err)
		}
		*item.path = strings.TrimSpace(string(b))
	}
	return nil
}

func enableInterfaceForwarding(vpn string) error {
	for _, path := range []string{
		"/proc/sys/net/ipv4/conf/all/forwarding",
		"/proc/sys/net/ipv6/conf/all/forwarding",
		filepath.Join("/proc/sys/net/ipv4/conf", vpn, "forwarding"),
		filepath.Join("/proc/sys/net/ipv6/conf", vpn, "forwarding"),
	} {
		if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
			return fmt.Errorf("enable forwarding at %s: %w", path, err)
		}
	}
	return nil
}

func restoreForwarding(state linuxHardLaunchState) {
	for _, item := range []struct{ path, value string }{
		{"/proc/sys/net/ipv4/conf/all/forwarding", state.ForwardAll4},
		{"/proc/sys/net/ipv6/conf/all/forwarding", state.ForwardAll6},
		{filepath.Join("/proc/sys/net/ipv4/conf", state.VPN, "forwarding"), state.ForwardVPN4},
		{filepath.Join("/proc/sys/net/ipv6/conf", state.VPN, "forwarding"), state.ForwardVPN6},
	} {
		if item.value != "" {
			_ = os.WriteFile(item.path, []byte(item.value), 0o644)
		}
	}
}

func setForwarding(enabled bool) error {
	v := "0"
	if enabled {
		v = "1"
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(v), 0o644); err != nil {
		return fmt.Errorf("set IPv4 forwarding=%s: %w", v, err)
	}
	return nil
}

func setForwarding6(enabled bool) error {
	v := "0"
	if enabled {
		v = "1"
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte(v), 0o644); err != nil {
		return fmt.Errorf("set IPv6 forwarding=%s: %w", v, err)
	}
	return nil
}

func moveSelfToCgroup(path string) error {
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		return fmt.Errorf("attach protected launcher to cgroup: %w", err)
	}
	return nil
}

func currentCgroupPath() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" {
			path := strings.TrimSpace(parts[2])
			if filepath.IsAbs(path) {
				return filepath.Join("/sys/fs/cgroup", path), nil
			}
		}
	}
	return "", errors.New("unified cgroup path not found")
}

func netInterface(name string) (string, error) {
	out, err := exec.Command("ip", "link", "show", "dev", name).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("VPN interface %q is unavailable: %w", name, err)
	}
	if !strings.Contains(string(out), "UP") {
		return "", fmt.Errorf("VPN interface %q is down", name)
	}
	return name, nil
}

func (m *Manager) KernelHardState() (linuxHardLaunchState, error) {
	return readHardState(m.Config().Root)
}

func (m *Manager) KernelHardStateActive() bool {
	_, err := m.KernelHardState()
	return err == nil
}

func (m *Manager) KernelHardProcessRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hardCmd != nil && m.hardCmd.Process != nil
}

func (m *Manager) KernelHardAvailable() error { return LinuxHardIsolationAvailable() }

func (m *Manager) KernelHardPreflight(ctx context.Context) error {
	_ = ctx
	if err := LinuxHardIsolationAvailable(); err != nil {
		return err
	}
	if strings.TrimSpace(m.Config().VPNInterface) == "" {
		return errors.New("kernel-hard mode requires an explicit VPN interface")
	}
	return nil
}

// LaunchKernelHard authorizes one fixed-function privileged launcher. The
// launcher owns the namespace and remains attached to the protected IDE until
// it exits, so cleanup is coupled to the protected process lifetime.
func (m *Manager) LaunchKernelHard(executable string, env []string) error {
	if err := m.KernelHardPreflight(context.Background()); err != nil {
		return err
	}
	uid := uint32(os.Getuid())
	envPath := filepath.Join(m.Config().Root, "kernel-hard-env.json")
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if err := os.WriteFile(envPath, b, 0o600); err != nil {
		return fmt.Errorf("write protected launch environment: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	pkexec := findLinuxCommand("pkexec", "/usr/bin/pkexec")
	if pkexec == "" {
		return errors.New("kernel-hard launch requires pkexec")
	}
	cmd := exec.Command(pkexec, self, "__linux-hard-launch", m.Config().Root, m.Config().VPNInterface, executable, envPath, strconv.FormatUint(uint64(uid), 10))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("authorize kernel-hard launcher: %w", err)
	}
	m.mu.Lock()
	m.hardCmd = cmd
	m.mode = ModeAgentTunnel
	m.mu.Unlock()
	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		if m.hardCmd == cmd {
			m.hardCmd = nil
			m.mode = ModeOff
		}
		m.mu.Unlock()
		if err != nil {
			m.log("error", "kernel-hard launcher exited: "+err.Error())
		}
	}()
	return nil
}
