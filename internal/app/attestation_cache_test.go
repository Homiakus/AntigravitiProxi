package app

import (
	"strings"
	"testing"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/proxy"
)

func TestEgressEvidenceCacheSuccessAndFailureTTL(t *testing.T) {
	var c egressEvidenceCache
	base := time.Date(2026, 9, 5, 6, 0, 0, 0, time.UTC)

	success := proxy.PublicEgressAttestation{Available: true, Detail: "ok"}
	until := c.store("pid=10|vpn=vpn0", success, base)
	if want := base.Add(egressEvidenceSuccessTTL); !until.Equal(want) {
		t.Fatalf("success until=%s want=%s", until, want)
	}
	got, gotUntil, ok := c.lookup("pid=10|vpn=vpn0", base.Add(egressEvidenceSuccessTTL-time.Nanosecond))
	if !ok || !got.Available || got.Detail != "ok" || !gotUntil.Equal(until) {
		t.Fatalf("fresh success lookup=(%#v,%s,%v)", got, gotUntil, ok)
	}
	if _, _, ok := c.lookup("pid=10|vpn=vpn0", until); ok {
		t.Fatal("entry must expire exactly at fresh-until")
	}

	failure := proxy.PublicEgressAttestation{Available: false, Detail: "observer unavailable"}
	until = c.store("pid=10|vpn=vpn0", failure, base)
	if want := base.Add(egressEvidenceFailureTTL); !until.Equal(want) {
		t.Fatalf("failure until=%s want=%s", until, want)
	}
}

func TestEgressEvidenceCacheRejectsDifferentRuntimeIdentity(t *testing.T) {
	var c egressEvidenceCache
	base := time.Now().UTC()
	c.store("pid=10|vpn=vpn0", proxy.PublicEgressAttestation{Available: true}, base)

	for _, key := range []string{"pid=11|vpn=vpn0", "pid=10|vpn=vpn1", ""} {
		if _, _, ok := c.lookup(key, base.Add(time.Second)); ok {
			t.Fatalf("cache entry leaked across runtime identity key %q", key)
		}
	}
}

func TestEgressEvidenceCacheClearInvalidatesEvidence(t *testing.T) {
	var c egressEvidenceCache
	base := time.Now().UTC()
	c.store("pid=10|vpn=vpn0", proxy.PublicEgressAttestation{Available: true}, base)
	c.clear()
	if _, _, ok := c.lookup("pid=10|vpn=vpn0", base.Add(time.Second)); ok {
		t.Fatal("clear must invalidate cached egress evidence")
	}
}

func TestServerInvalidateEgressEvidenceClearsAndPublishes(t *testing.T) {
	hub := newEventHub()
	s := &Server{events: hub}
	base := time.Now().UTC()
	s.egressCache.store("pid=10|vpn=vpn0", proxy.PublicEgressAttestation{Available: true}, base)

	ch, cancel := hub.subscribe()
	defer cancel()
	s.invalidateEgressEvidence("test lifecycle boundary")

	if _, _, ok := s.egressCache.lookup("pid=10|vpn=vpn0", base.Add(time.Second)); ok {
		t.Fatal("server lifecycle invalidation must clear cached evidence")
	}
	select {
	case e := <-ch:
		if e.Level != "info" || !strings.Contains(e.Message, "test lifecycle boundary") {
			t.Fatalf("unexpected invalidation event: %#v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("expected lifecycle invalidation event")
	}
}
