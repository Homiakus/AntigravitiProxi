package diagnostics

import (
	"context"
	"testing"
	"time"
)

func TestCollectWithCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	snapshot, err := Collect(ctx, []string{"antigravity.google", "oauth2.googleapis.com"})
	if err != nil {
		t.Fatalf("Collect returned unexpected error: %v", err)
	}
	if len(snapshot.DNS) != 2 {
		t.Fatalf("expected 2 DNS entries, got %d", len(snapshot.DNS))
	}
}

func TestCollectTimeoutBounded(t *testing.T) {
	timeout := 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	snapshot, err := Collect(ctx, []string{"antigravity.google"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if elapsed > timeout+2*time.Second {
		t.Fatalf("Collect took too long: %v (timeout was %v)", elapsed, timeout)
	}
	if len(snapshot.DNS) != 1 || snapshot.DNS[0].Domain != "antigravity.google" {
		t.Fatalf("unexpected snapshot DNS results: %#v", snapshot.DNS)
	}
}
