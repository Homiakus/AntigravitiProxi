//go:build linux

package proxy

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestMissingLinuxCapabilitiesAcceptsFullSet(t *testing.T) {
	got := missingLinuxCapabilities("/tmp/sing-box cap_dac_read_search,cap_net_admin,cap_net_raw,cap_sys_ptrace=ep")
	if len(got) != 0 {
		t.Fatalf("missing=%v want none", got)
	}
}

func TestMissingLinuxCapabilitiesReportsExactMissingSet(t *testing.T) {
	got := missingLinuxCapabilities("/tmp/sing-box cap_net_admin,cap_net_raw=ep")
	want := []string{"cap_sys_ptrace", "cap_dac_read_search"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missing=%v want %v", got, want)
	}
}

func TestLinuxCapabilitySpecContainsEveryRequiredCapability(t *testing.T) {
	if got := missingLinuxCapabilities(linuxTunnelCapabilitySpec); len(got) != 0 {
		t.Fatalf("capability spec is incomplete, missing=%v", got)
	}
}

func TestPrivilegeBootstrapDoesNotImplementPasswordPiping(t *testing.T) {
	b, err := os.ReadFile("tunnel_host_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, forbidden := range []string{"sudo -S", "--stdin", "SUDO_ASKPASS=", "password="} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("privilege bootstrap must not handle passwords directly; found %q", forbidden)
		}
	}
	for _, required := range []string{"pkexec", "cmd.Stdin = os.Stdin", "linuxTunnelCapabilitySpec"} {
		if !strings.Contains(s, required) {
			t.Fatalf("privilege bootstrap security contract missing %q", required)
		}
	}
}

func TestPrivilegedManagedBinaryTargetAcceptsOwnedManagedLayout(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "AntigravitiProxi", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(binDir, "sing-box")
	if err := os.WriteFile(binary, []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PKEXEC_UID", strconv.Itoa(os.Getuid()))
	t.Setenv("SUDO_UID", "")
	if err := validatePrivilegedManagedBinaryTarget(binary); err != nil {
		t.Fatalf("valid managed target rejected: %v", err)
	}
}

func TestPrivilegedManagedBinaryTargetRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "AntigravitiProxi", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "real-sing-box")
	if err := os.WriteFile(target, []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(binDir, "sing-box")
	if err := os.Symlink(target, binary); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PKEXEC_UID", strconv.Itoa(os.Getuid()))
	if err := validatePrivilegedManagedBinaryTarget(binary); err == nil || !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("symlink target should be rejected, got %v", err)
	}
}

func TestPrivilegedManagedBinaryTargetRejectsUnexpectedLayout(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "sing-box")
	if err := os.WriteFile(binary, []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PKEXEC_UID", strconv.Itoa(os.Getuid()))
	if err := validatePrivilegedManagedBinaryTarget(binary); err == nil || !strings.Contains(err.Error(), "ownership boundary") {
		t.Fatalf("unexpected layout should be rejected, got %v", err)
	}
}

func TestMissingLinuxCapabilitiesRejectsInactiveOrMisleadingNames(t *testing.T) {
	for _, value := range []string{
		"/tmp/sing-box cap_net_admin,cap_net_raw,cap_sys_ptrace,cap_dac_read_search=p",
		"/tmp/cap_net_admin,cap_net_raw,cap_sys_ptrace,cap_dac_read_search=ep/sing-box",
		"/tmp/sing-box cap_net_admin_extra,cap_net_raw_extra,cap_sys_ptrace_extra,cap_dac_read_search_extra=ep",
	} {
		if got := missingLinuxCapabilities(value); !reflect.DeepEqual(got, requiredLinuxTunnelCapabilities) {
			t.Errorf("%q: missing=%v", value, got)
		}
	}
}

func TestMissingLinuxCapabilitiesAcceptsSeparateClauses(t *testing.T) {
	if got := missingLinuxCapabilities("/tmp/sing-box cap_net_admin,cap_net_raw=ep cap_sys_ptrace,cap_dac_read_search=eip"); len(got) != 0 {
		t.Fatalf("missing=%v", got)
	}
}

func TestPrivilegedRecoveryAcceptsOnlyReservedOwnership(t *testing.T) {
	owned := reservedPlatformOwnership()
	if err := validateReservedTunnelOwnership(owned); err != nil {
		t.Fatalf("reserved ownership rejected: %v", err)
	}
	owned.NewRouteTablesV4 = []string{"4242"}
	if err := validateReservedTunnelOwnership(owned); err == nil {
		t.Fatal("foreign route table accepted for privileged recovery")
	}
}

func TestUpstreamHostRoutesPreserveOnlyExternalGatewayHosts(t *testing.T) {
	raw := []byte(`[{"dst":"185.228.72.253","gateway":"192.168.1.254","dev":"wlo1"},{"dst":"default","gateway":"192.168.1.254","dev":"wlo1"},{"dst":"192.168.0.0/16","gateway":"192.168.1.254","dev":"wlo1"},{"dst":"1.1.1.1","gateway":"10.8.1.1","dev":"amn0"},{"dst":"2001:db8::1/128","gateway":"fe80::1","dev":"wlo1"}]`)
	got, err := parseUpstreamHostRoutes(raw, "amn0")
	want := []string{"185.228.72.253/32", "2001:db8::1/128"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v err=%v", got, err)
	}
}
