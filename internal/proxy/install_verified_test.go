package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestVerifiedManagedBinaryDetectsTampering(t *testing.T) {
	root := t.TempDir()
	m := New(Config{Root: root, SingBoxVer: DefaultSingBoxVersion}, nil)
	if err := os.MkdirAll(filepath.Dir(m.ManagedPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.ManagedPath(), []byte("known verified fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	hash, err := sha256File(m.ManagedPath())
	if err != nil {
		t.Fatal(err)
	}
	asset := assetNameFor(runtime.GOOS, runtime.GOARCH, DefaultSingBoxVersion)
	p := managedProvenance{
		Version:       DefaultSingBoxVersion,
		Asset:         asset,
		ReleaseDigest: "sha256:test-fixture",
		BinarySHA256:  hash,
		VerifiedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.provenancePath(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, detail := m.verifiedManagedBinary(m.ManagedPath(), asset, DefaultSingBoxVersion); !ok {
		t.Fatalf("expected verified fixture, detail=%s", detail)
	}

	if err := os.WriteFile(m.ManagedPath(), []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ok, detail := m.verifiedManagedBinary(m.ManagedPath(), asset, DefaultSingBoxVersion); ok {
		t.Fatalf("tampered binary remained trusted, detail=%s", detail)
	}
}

func TestVerifiedManagedBinaryRejectsMissingDigestEvidence(t *testing.T) {
	root := t.TempDir()
	m := New(Config{Root: root, SingBoxVer: DefaultSingBoxVersion}, nil)
	if err := os.MkdirAll(filepath.Dir(m.ManagedPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.ManagedPath(), []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	hash, _ := sha256File(m.ManagedPath())
	asset := assetNameFor(runtime.GOOS, runtime.GOARCH, DefaultSingBoxVersion)
	p := managedProvenance{Version: DefaultSingBoxVersion, Asset: asset, BinarySHA256: hash}
	b, _ := json.Marshal(p)
	if err := os.WriteFile(m.provenancePath(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.verifiedManagedBinary(m.ManagedPath(), asset, DefaultSingBoxVersion); ok {
		t.Fatal("provenance without release digest evidence must not be trusted")
	}
}
