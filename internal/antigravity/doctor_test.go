package antigravity

import (
	"strings"
	"testing"
)

func TestDoctorAdviceSeparatesBackendAndTransportCauses(t *testing.T) {
	cases := []struct {
		kind string
		want string
	}{
		{"geo_eligibility", "geo/eligibility"},
		{"account_eligibility", "account/credential"},
		{"quota", "quota"},
		{"backend_unavailable", "backend"},
		{"auth", "token refresh"},
		{"mcp", "MCP"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			summary, steps := doctorAdvice(tc.kind, 1, 1)
			joined := strings.ToLower(summary + " " + strings.Join(steps, " "))
			if !strings.Contains(joined, strings.ToLower(tc.want)) {
				t.Fatalf("doctor advice %q omitted classification %q: %s", tc.kind, tc.want, joined)
			}
		})
	}
}

func TestSafeSnippetRedactsCredentials(t *testing.T) {
	text := `request failed Authorization: Bearer abcdefghijklmnop access_token="secret-value-123"`
	got := safeSnippet(text, 0, len(text))
	for _, secret := range []string{"abcdefghijklmnop", "secret-value-123"} {
		if strings.Contains(got, secret) {
			t.Fatalf("credential leaked in snippet: %q", got)
		}
	}
}
