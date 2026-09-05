package antigravity

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/atomicfile"
)

func TestHostsOverrideMetadataExpiryDecision(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	metadata := hostsOverrideMetadata{Domain: "daily-cloudcode-pa.googleapis.com", IP: "192.0.2.7", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}
	b, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeMetadataForTest(filepath.Join(dir, "hosts-override.json"), b); err != nil {
		t.Fatal(err)
	}
	// No real system hosts mutation is attempted by this fixture. The malformed
	// ownership state must be rejected before any cleanup is reported.
	if removed, err := ExpireHostsOverride(dir, now); err == nil || removed {
		t.Fatalf("unproven hosts ownership removed=%v err=%v", removed, err)
	}
}

func writeMetadataForTest(path string, b []byte) error {
	return atomicfile.Write(path, b, 0o600)
}
