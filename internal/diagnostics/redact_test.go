package diagnostics

import (
	"strings"
	"testing"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/platform"
)

func TestRedactSupportData(t *testing.T) {
	got := Redact(`Authorization: Bearer abcdefghijklmnop access_token="secret-value-123" user@example.com 192.0.2.7 /home/alice/.config/AntigravitiProxi C:\Users\Alice\secret.txt`)
	for _, forbidden := range []string{"abcdefghijklmnop", "secret-value-123", "user@example.com", "192.0.2.7"} {
		if contains(got, forbidden) {
			t.Fatalf("sensitive value leaked: %q in %q", forbidden, got)
		}
	}
	for _, forbidden := range []string{"/home/alice", `C:\Users\Alice`} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("user path leaked: %q in %q", forbidden, got)
		}
	}
}

func FuzzRedactKnownSecrets(f *testing.F) {
	f.Add("Bearer abcdefghijklmnop user@example.com /home/alice/file.txt 192.0.2.7")
	f.Add(`refresh_token="fixture-secret" C:\Users\Alice\token.txt`)
	f.Fuzz(func(t *testing.T, input string) {
		got := Redact(input)
		if strings.Contains(got, "user@example.com") || strings.Contains(got, "/home/alice") || strings.Contains(got, `C:\Users\Alice`) {
			t.Fatalf("known fixture secret leaked: %q", got)
		}
	})
}

func TestFormatTextRedactsSupportFacingSnapshot(t *testing.T) {
	text := FormatText(Snapshot{
		Time:       time.Unix(0, 0).UTC(),
		PublicIP:   "198.51.100.9",
		PublicGeo:  "user@example.com / secret-token",
		Interfaces: []platform.Interface{{Name: "vpn0", Addresses: []string{"192.0.2.7"}}},
		DNS:        []DNSComparison{{Domain: "backend.example", System: []string{"203.0.113.8"}}},
	})
	for _, forbidden := range []string{"198.51.100.9", "192.0.2.7", "203.0.113.8", "user@example.com"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("support-facing text leaked %q: %s", forbidden, text)
		}
	}
}

func contains(value, needle string) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
