//go:build windows

package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSensitiveFileACLHardeningFixture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box-api-secret")
	if err := os.WriteFile(path, []byte("fixture-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := hardenSensitiveFile(path); err != nil {
		t.Fatal(err)
	}
}
