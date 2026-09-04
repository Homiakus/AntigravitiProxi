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
