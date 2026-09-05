//go:build windows

package proxy

import (
	"net"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestParseWindowsNetstatOwnersExactEndpointAndCandidateFilter(t *testing.T) {
	raw := `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    10.20.30.40:51515      142.250.1.1:443        ESTABLISHED     1200
  TCP    10.20.30.40:51515      142.250.1.2:443        ESTABLISHED     2200
  TCP    10.20.30.40:51516      142.250.1.3:443        ESTABLISHED     3300
  UDP    10.20.30.40:51515      *:*                                    4400
`
	owners, matches := parseWindowsNetstatOwners(raw, "tcp", net.ParseIP("10.20.30.40"), 51515, []int{2200, 3300})
	if matches != 2 {
		t.Fatalf("matches=%d want=2", matches)
	}
	if want := []int{2200}; !reflect.DeepEqual(owners, want) {
		t.Fatalf("owners=%v want=%v", owners, want)
	}
}

func TestParseWindowsNetstatOwnersSurfacesAmbiguousCandidateOwnership(t *testing.T) {
	raw := `
  TCP    10.20.30.40:51515      142.250.1.1:443        ESTABLISHED     1200
  TCP    10.20.30.40:51515      142.250.1.2:443        ESTABLISHED     2200
`
	owners, matches := parseWindowsNetstatOwners(raw, "tcp", net.ParseIP("10.20.30.40"), 51515, []int{2200, 1200})
	if matches != 2 {
		t.Fatalf("matches=%d want=2", matches)
	}
	if want := []int{1200, 2200}; !reflect.DeepEqual(owners, want) {
		t.Fatalf("owners=%v want=%v", owners, want)
	}
}

func TestSplitWindowsRuntimeSourceIPv4AndIPv6Zone(t *testing.T) {
	cases := []struct {
		source string
		ip     string
		port   int
	}{
		{"127.0.0.1:443", "127.0.0.1", 443},
		{"[2001:db8::10]:8443", "2001:db8::10", 8443},
		{"[fe80::1%12]:5353", "fe80::1", 5353},
	}
	for _, tc := range cases {
		ip, port, err := splitWindowsRuntimeSource(tc.source)
		if err != nil {
			t.Fatalf("splitWindowsRuntimeSource(%q): %v", tc.source, err)
		}
		if !ip.Equal(net.ParseIP(tc.ip)) || port != tc.port {
			t.Fatalf("splitWindowsRuntimeSource(%q)=(%v,%d) want=(%s,%d)", tc.source, ip, port, tc.ip, tc.port)
		}
	}
	for _, bad := range []string{"", "127.0.0.1", "127.0.0.1:0", "host.invalid:443"} {
		if _, _, err := splitWindowsRuntimeSource(bad); err == nil {
			t.Fatalf("splitWindowsRuntimeSource(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestWindowsLiveSocketOwnershipFindsCurrentPID(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server net.Conn
	select {
	case server = <-accepted:
		defer server.Close()
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("accept timeout")
	}

	pid := os.Getpid()
	source := client.LocalAddr().String()
	deadline := time.Now().Add(3 * time.Second)
	var lastDetail string
	for {
		owners, detail, err := platformRuntimeConnectionOwners(source, "tcp", []int{pid})
		lastDetail = detail
		if err == nil && intSliceContains(owners, pid) {
			t.Logf("live Windows socket ownership proven: pid=%d source=%s detail=%s", pid, source, detail)
			return
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("live socket ownership failed: %v detail=%s", err, lastDetail)
			}
			t.Fatalf("live socket ownership did not resolve pid=%d source=%s detail=%s", pid, source, lastDetail)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func intSliceContains(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
