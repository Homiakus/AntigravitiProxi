package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteCreatesCompleteFileAndPreviousGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	first := []byte("{\"version\":1}\n")
	second := []byte("{\"version\":2}\n")

	if err := Write(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, second, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(second) {
		t.Fatalf("target = %q, want %q", got, second)
	}

	backup, err := os.ReadFile(path + ".previous-good")
	if err != nil {
		t.Fatal(err)
	}
	if string(backup) != string(first) {
		t.Fatalf("backup = %q, want %q", backup, first)
	}
}

func TestWriteRejectsEmptyPath(t *testing.T) {
	if err := Write("", []byte("x"), 0o600); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestWriteDirectDoesNotCreatePreviousGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	data := []byte("127.0.0.1 localhost\n")

	if err := WriteDirect(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatalf("got %q, want %q", got, data)
	}

	if _, err := os.Stat(path + ".previous-good"); !os.IsNotExist(err) {
		t.Fatalf(".previous-good should not exist for WriteDirect, err=%v", err)
	}
}
