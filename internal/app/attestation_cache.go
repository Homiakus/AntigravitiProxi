package app

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/proxy"
)

const (
	egressEvidenceSuccessTTL = 15 * time.Second
	egressEvidenceFailureTTL = 3 * time.Second
)

type egressEvidenceCache struct {
	mu    sync.Mutex
	key   string
	value proxy.PublicEgressAttestation
	until time.Time
	set   bool
}

func (c *egressEvidenceCache) lookup(key string, now time.Time) (proxy.PublicEgressAttestation, time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.set || c.key != key || !now.Before(c.until) {
		return proxy.PublicEgressAttestation{}, time.Time{}, false
	}
	return c.value, c.until, true
}

func (c *egressEvidenceCache) store(key string, value proxy.PublicEgressAttestation, now time.Time) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ttl := egressEvidenceFailureTTL
	if value.Available {
		ttl = egressEvidenceSuccessTTL
	}
	c.key = key
	c.value = value
	c.until = now.Add(ttl)
	c.set = true
	return c.until
}

func (c *egressEvidenceCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.key = ""
	c.value = proxy.PublicEgressAttestation{}
	c.until = time.Time{}
	c.set = false
}

func (s *Server) cachedPublicEgress(ctx context.Context) (value proxy.PublicEgressAttestation, freshUntil time.Time, cached bool) {
	// Managed PID + configured upstream identity make stale evidence from a
	// previous data-plane instance unusable automatically. A VPN can still
	// reconnect without changing either, so successful evidence is deliberately
	// short-lived (15 s) rather than treated as a durable fact.
	cfg := s.pm.Config()
	key := fmt.Sprintf("pid=%d|vpn=%s", s.pm.ManagedPID(), cfg.VPNInterface)
	now := time.Now().UTC()
	if value, until, ok := s.egressCache.lookup(key, now); ok {
		return value, until, true
	}

	value = s.pm.AttestPublicEgress(ctx)
	freshUntil = s.egressCache.store(key, value, time.Now().UTC())
	return value, freshUntil, false
}
