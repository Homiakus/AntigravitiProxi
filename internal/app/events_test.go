package app

import (
	"fmt"
	"testing"
	"time"
)

func TestEventHubHistoryReplayAndCancelSafety(t *testing.T) {
	hub := newEventHub()

	// Fill history with more items than channel buffer (buffer is 32)
	for i := 0; i < 60; i++ {
		hub.publish("info", fmt.Sprintf("event-%d", i))
	}

	ch, cancel := hub.subscribe()

	// Read a few events
	for i := 0; i < 5; i++ {
		select {
		case e := <-ch:
			if e.Level != "info" {
				t.Fatalf("expected level info, got %s", e.Level)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatal("timed out waiting for event")
		}
	}

	// Immediate cancel while background goroutine still has events to send
	cancel()
	// Second cancel must be safe (idempotent)
	cancel()

	// Publish new event - should not be received on cancelled subscriber
	hub.publish("info", "new-event")

	// Wait a moment to ensure no panic in background goroutine
	time.Sleep(50 * time.Millisecond)

	hub.mu.Lock()
	clientCount := len(hub.clients)
	hub.mu.Unlock()

	if clientCount != 0 {
		t.Fatalf("expected 0 clients after cancel, got %d", clientCount)
	}
}
