package platform

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type Interface struct {
	Name      string   `json:"name"`
	Index     int      `json:"index"`
	Flags     []string `json:"flags"`
	Addresses []string `json:"addresses"`
	LikelyVPN bool     `json:"likely_vpn"`
}

func Interfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil { return nil, err }
	out := make([]Interface, 0, len(ifaces))
	for _, it := range ifaces {
		addrs, _ := it.Addrs()
		flags := make([]string, 0, 4)
		if it.Flags&net.FlagUp != 0 { flags = append(flags, "up") }
		if it.Flags&net.FlagLoopback != 0 { flags = append(flags, "loopback") }
		if it.Flags&net.FlagPointToPoint != 0 { flags = append(flags, "point-to-point") }
		if it.Flags&net.FlagMulticast != 0 { flags = append(flags, "multicast") }
		addrStrings := make([]string, 0, len(addrs))
		for _, a := range addrs { addrStrings = append(addrStrings, a.String()) }
		n := strings.ToLower(it.Name)
		likely := strings.Contains(n, "amnezia") || strings.Contains(n, "vpn") || strings.Contains(n, "wireguard") || strings.HasPrefix(n, "wg") || strings.HasPrefix(n, "tun") || strings.Contains(n, "wintun") || strings.Contains(n, "tailscale") || strings.Contains(n, "outline")
		out = append(out, Interface{Name: it.Name, Index: it.Index, Flags: flags, Addresses: addrStrings, LikelyVPN: likely})
	}
	sort.SliceStable(out, func(i, j int) bool { if out[i].LikelyVPN != out[j].LikelyVPN { return out[i].LikelyVPN }; return out[i].Name < out[j].Name })
	return out, nil
}

func ConfigDir() (string, error) { base, err := os.UserConfigDir(); if err != nil { return "", err }; return filepath.Join(base, "AntigravitiProxi"), nil }
func CacheDir() (string, error) { base, err := os.UserCacheDir(); if err != nil { return "", err }; return filepath.Join(base, "AntigravitiProxi"), nil }
func HostsPath() string { if runtime.GOOS == "windows" { root := os.Getenv("SystemRoot"); if root == "" { root = `C:\Windows` }; return filepath.Join(root, "System32", "drivers", "etc", "hosts") }; return "/etc/hosts" }
