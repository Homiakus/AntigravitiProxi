package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRuntimeConnections(t *testing.T) {
	raw := "/opt/Antigravity/antigravity\tvpn-direct\tcloudcode-pa.googleapis.com:443\ttun/agent-tun\ttcp\n" +
		"/usr/bin/curl\tsystem-direct\texample.com:443\ttun/agent-tun\ttcp\n"
	got, err := parseRuntimeConnections(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d connections", len(got))
	}
	if got[0].Process != "/opt/Antigravity/antigravity" || got[0].Outbound != "vpn-direct" {
		t.Fatalf("unexpected first connection: %#v", got[0])
	}
	if got[1].Outbound != "system-direct" {
		t.Fatalf("unexpected second connection: %#v", got[1])
	}
}

func TestParseRuntimeConnectionsRejectsSchemaDrift(t *testing.T) {
	if _, err := parseRuntimeConnections("process\tvpn-direct\tdestination\n"); err == nil {
		t.Fatal("expected column-count mismatch to fail closed")
	}
}

func TestEnsureAPISecretPersistsAndReusesStrongSecret(t *testing.T) {
	root := t.TempDir()
	first, err := ensureAPISecret(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ensureAPISecret(root)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first) != 64 {
		t.Fatalf("secret persistence mismatch: first=%d second=%d equal=%v", len(first), len(second), first == second)
	}
	st, err := os.Stat(filepath.Join(root, "sing-box-api-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("API secret is too permissive: %o", st.Mode().Perm())
	}
}

func TestAgentRouteAttestationClassifiesRuntimeDecisions(t *testing.T) {
	cases := []struct {
		path  string
		known bool
	}{
		{"C:/Users/u/AppData/Local/Programs/Antigravity/Antigravity.exe", true},
		{"/opt/antigravity/language_server", true},
		{"/tmp/agy", true},
		{"/usr/bin/curl", false},
	}
	for _, tc := range cases {
		if got := looksLikeAntigravityProcess(tc.path); got != tc.known {
			t.Fatalf("looksLikeAntigravityProcess(%q)=%v want=%v", tc.path, got, tc.known)
		}
	}
}
