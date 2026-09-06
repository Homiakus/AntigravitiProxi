package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRootServesIndexWithoutRedirect(t *testing.T) {
	s := &Server{csrf: "test-token"}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:48765/", nil)
	rr := httptest.NewRecorder()

	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200; Location=%q body=%q", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	if location := rr.Header().Get("Location"); location != "" {
		t.Fatalf("GET / unexpectedly redirected to %q", location)
	}
	if !strings.Contains(rr.Body.String(), "AntigravitiProxi") {
		t.Fatalf("GET / did not serve embedded index.html")
	}

	cookies := rr.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "agp_csrf" && c.Value == "test-token" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("GET / did not set agp_csrf cookie")
	}
}

func TestStaticAssetsRemainDirectlyReachable(t *testing.T) {
	s := &Server{csrf: "test-token"}
	for _, path := range []string{"/app.js", "/styles.css", "/manifest.webmanifest", "/sw.js"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:48765"+path, nil)
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200; Location=%q", path, rr.Code, rr.Header().Get("Location"))
			}
		})
	}
}

func TestSecurityHeadersRejectsInvalidHost(t *testing.T) {
	s := &Server{csrf: "test-token"}

	// Rebinding attack attempt with an external hostname
	badReq := httptest.NewRequest(http.MethodGet, "http://attacker.example.com:48765/", nil)
	badRR := httptest.NewRecorder()
	s.Handler().ServeHTTP(badRR, badReq)
	if badRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for external Host, got %d", badRR.Code)
	}

	// Valid loopback hosts must succeed
	for _, validHost := range []string{"127.0.0.1:48765", "localhost:48765", "[::1]:48765", "127.0.0.1"} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:48765/", nil)
		req.Host = validHost
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for valid host %q, got %d", validHost, rr.Code)
		}
	}
}
