package app

import (
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
