package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Homiakus/AntigravitiProxi/internal/proxy"
)

func TestNetworkAttestationEndpointIsReadOnlyAndReturnsIdleEvidence(t *testing.T) {
	pm := proxy.New(proxy.Config{
		Root:         t.TempDir(),
		Host:         "127.0.0.1",
		Port:         17899,
		VPNInterface: "",
		DNSProvider:  "cloudflare",
		SingBoxVer:   proxy.DefaultSingBoxVersion,
	}, nil)
	s := &Server{
		pm:     pm,
		events: newEventHub(),
		csrf:   "test-csrf",
	}

	req := httptest.NewRequest(http.MethodGet, "/api/attestation", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/attestation status=%d body=%q", rr.Code, rr.Body.String())
	}
	var got NetworkAttestationReport
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v body=%q", err, rr.Body.String())
	}
	if got.State != AssuranceIdle {
		t.Fatalf("state=%q want=%q detail=%q", got.State, AssuranceIdle, got.Detail)
	}
	if got.Detail == "" {
		t.Fatal("attestation endpoint must explain its evidence state")
	}
	if got.EgressCached || got.EgressFreshUntil != nil {
		t.Fatalf("idle report must not expose stale egress cache metadata: cached=%v fresh_until=%v", got.EgressCached, got.EgressFreshUntil)
	}
	if csp := rr.Header().Get("Content-Security-Policy"); csp == "" {
		t.Fatal("attestation endpoint must retain control-plane security headers")
	}

	// Read-only evidence does not require the mutation CSRF token, while a
	// method change must not accidentally hit the GET handler.
	post := httptest.NewRequest(http.MethodPost, "/api/attestation", nil)
	postRR := httptest.NewRecorder()
	s.Handler().ServeHTTP(postRR, post)
	if postRR.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/attestation status=%d want=%d", postRR.Code, http.StatusMethodNotAllowed)
	}
}
