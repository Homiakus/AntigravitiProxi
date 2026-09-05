//go:build linux

package proxy

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSplitRuntimeSource(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port int
	}{
		{"127.0.0.1:443", "127.0.0.1", 443},
		{"10.250.0.2:51000", "10.250.0.2", 51000},
		{"[2001:db8::1]:8443", "2001:db8::1", 8443},
	}
	for _, tc := range cases {
		ip, port, err := splitRuntimeSource(tc.in)
		if err != nil {
			t.Fatalf("splitRuntimeSource(%q): %v", tc.in, err)
		}
		if !ip.Equal(net.ParseIP(tc.ip)) || port != tc.port {
			t.Fatalf("splitRuntimeSource(%q)=(%v,%d) want=(%s,%d)", tc.in, ip, port, tc.ip, tc.port)
		}
	}
	for _, bad := range []string{"", "127.0.0.1", "127.0.0.1:0", "host.invalid:443"} {
		if _, _, err := splitRuntimeSource(bad); err == nil {
			t.Fatalf("splitRuntimeSource(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestLinuxSourceSocketInodesMatchesExactLocalEndpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tcp")
	content := "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
		"   0: 0100007F:1F90 0200007F:0050 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 20 4 30 10 -1\n" +
		"   1: 0100007F:1F91 0200007F:0050 01 00000000:00000000 00:00000000 00000000 1000 0 54321 1 0000000000000000 20 4 30 10 -1\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := linuxSourceSocketInodes(path, net.ParseIP("127.0.0.1"), 8080)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct{}{"12345": {}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inodes=%v want=%v", got, want)
	}
}

func TestUniqueSortedPositiveInts(t *testing.T) {
	got := uniqueSortedPositiveInts([]int{7, -1, 3, 7, 0, 2, 3})
	want := []int{2, 3, 7}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}
