//go:build linux

package proxy

import "testing"

func TestDecodeProcEndpointIPv4Loopback(t *testing.T) {
	ip, port, err := decodeProcEndpoint("0100007F:1ED2") // 127.0.0.1:7890
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "127.0.0.1" {
		t.Fatalf("ip=%s", got)
	}
	if port != 7890 {
		t.Fatalf("port=%d", port)
	}
}

func TestDecodeProcEndpointIPv6Loopback(t *testing.T) {
	ip, port, err := decodeProcEndpoint("00000000000000000000000001000000:1ED2")
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "::1" {
		t.Fatalf("ip=%s", got)
	}
	if port != 7890 {
		t.Fatalf("port=%d", port)
	}
}
