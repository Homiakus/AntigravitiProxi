package proxy

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestLoadTunnelJournalFallsBackToValidatedPreviousGood(t *testing.T) {
	m := New(Config{Root: t.TempDir()}, nil)
	j := TunnelStateJournal{
		SchemaVersion: networkStateSchema,
		Phase:         "active",
		OperationID:   "op-current",
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
		Before:        NetworkSnapshot{Platform: "linux"},
		Owned:         OwnedNetworkDelta{TunnelInterface: agentTunName},
	}
	b, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.networkJournalPreviousGoodPath(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.networkJournalPath(), []byte(`{"schema_version":1,"phase":`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := m.loadTunnelJournal()
	if err != nil {
		t.Fatalf("load with previous-good fallback: %v", err)
	}
	if got == nil || got.OperationID != "op-current" || !got.RecoveredFromPreviousGood {
		t.Fatalf("unexpected recovered journal: %#v", got)
	}
	if got.LastError == "" {
		t.Fatal("fallback recovery must retain corruption evidence")
	}
	status := m.NetworkJournalStatus()
	if !status.Open || status.Phase != "active" {
		t.Fatalf("fallback journal must remain an open recovery transaction: %#v", status)
	}
}

func TestLoadTunnelJournalRejectsPreviousGoodFromAlreadyCleanOperation(t *testing.T) {
	m := New(Config{Root: t.TempDir()}, nil)
	old := TunnelStateJournal{
		SchemaVersion: networkStateSchema,
		Phase:         "active",
		OperationID:   "op-old",
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
		Before:        NetworkSnapshot{Platform: "linux"},
		Owned:         OwnedNetworkDelta{TunnelInterface: agentTunName},
	}
	backup, _ := json.Marshal(old)
	if err := os.WriteFile(m.networkJournalPreviousGoodPath(), backup, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.networkJournalPath(), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	clean := old
	clean.Phase = "clean"
	cleanRaw, _ := json.Marshal(clean)
	if err := os.WriteFile(m.lastCleanNetworkJournalPath(), cleanRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := m.loadTunnelJournal(); err == nil {
		t.Fatal("stale previous-good from an already-clean operation must be rejected")
	}
}

func TestDecodeTunnelJournalRejectsUnknownPhaseAndMissingOperationID(t *testing.T) {
	cases := []TunnelStateJournal{
		{SchemaVersion: networkStateSchema, Phase: "mystery", OperationID: "op"},
		{SchemaVersion: networkStateSchema, Phase: "active", OperationID: ""},
	}
	for _, tc := range cases {
		b, _ := json.Marshal(tc)
		if _, err := decodeTunnelJournal(b); err == nil {
			t.Fatalf("invalid journal accepted: %#v", tc)
		}
	}
}

func TestPlatformProcessIdentityDistinguishesCurrentProcess(t *testing.T) {
	identity, err := platformProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatalf("current process identity: %v", err)
	}
	if identity == "" {
		t.Fatal("current process identity is empty")
	}
	if _, err := platformProcessIdentity(-1); err == nil {
		t.Fatal("negative PID unexpectedly accepted")
	}
}

func TestPersistCleanJournalRemovesOpenAndPreviousGood(t *testing.T) {
	m := New(Config{Root: t.TempDir()}, nil)
	j := &TunnelStateJournal{
		SchemaVersion: networkStateSchema,
		Phase:         "clean",
		OperationID:   "op-clean",
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	if err := os.WriteFile(m.networkJournalPath(), []byte("open"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.networkJournalPreviousGoodPath(), []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.persistCleanJournal(j); err != nil {
		t.Fatalf("persist clean journal: %v", err)
	}
	if _, err := os.Stat(m.networkJournalPath()); !os.IsNotExist(err) {
		t.Fatalf("open journal still exists: %v", err)
	}
	if _, err := os.Stat(m.networkJournalPreviousGoodPath()); !os.IsNotExist(err) {
		t.Fatalf("previous-good journal still exists: %v", err)
	}
	if _, err := os.Stat(m.lastCleanNetworkJournalPath()); err != nil {
		t.Fatalf("last-clean evidence missing: %v", err)
	}
}
