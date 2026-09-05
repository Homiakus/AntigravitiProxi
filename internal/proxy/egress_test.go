package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseObservedIP(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{name: "plain-v4", body: "203.0.113.7\n", want: "203.0.113.7"},
		{name: "plain-v6", body: "2001:db8::7\n", want: "2001:db8::7"},
		{name: "cloudflare-trace", body: "fl=123\nip=198.51.100.9\nts=1\n", want: "198.51.100.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip, err := parseObservedIP(tc.body)
			if err != nil {
				t.Fatal(err)
			}
			if ip.String() != tc.want {
				t.Fatalf("got %q want %q", ip.String(), tc.want)
			}
		})
	}
	if _, err := parseObservedIP("hello\nworld\n"); err == nil {
		t.Fatal("invalid observer response must fail closed")
	}
}

func TestProbeOneEgressProducesStructuredEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Cache-Control"); got != "no-cache" {
			t.Fatalf("Cache-Control=%q", got)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("203.0.113.44\n"))
	}))
	defer srv.Close()

	e := probeOneEgress(context.Background(), egressHTTPClient(nil), egressProbeProvider{
		Name: "fixture",
		URL:  srv.URL,
	}, "system-direct")
	if !e.OK {
		t.Fatalf("probe failed: %#v", e)
	}
	if e.ObservedIP != "203.0.113.44" || e.Family != "ipv4" || e.Via != "system-direct" || e.Provider != "fixture" {
		t.Fatalf("unexpected evidence: %#v", e)
	}
}

func TestProbeOneEgressRejectsNon2xxAndGarbage(t *testing.T) {
	badStatus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusBadGateway)
	}))
	defer badStatus.Close()
	if e := probeOneEgress(context.Background(), egressHTTPClient(nil), egressProbeProvider{Name: "bad-status", URL: badStatus.URL}, "test"); e.OK || e.HTTPStatus != http.StatusBadGateway {
		t.Fatalf("expected HTTP failure evidence, got %#v", e)
	}

	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-an-ip"))
	}))
	defer garbage.Close()
	if e := probeOneEgress(context.Background(), egressHTTPClient(nil), egressProbeProvider{Name: "garbage", URL: garbage.URL}, "test"); e.OK || e.Error == "" {
		t.Fatalf("expected parse failure evidence, got %#v", e)
	}
}
