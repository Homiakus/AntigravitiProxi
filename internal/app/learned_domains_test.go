package app

import "testing"

func TestLearnedDomainsRequireReviewedHostnames(t *testing.T) {
	got := normalizeLearnedDomains([]string{" Agent.New-Google.Test ", "agent.new-google.test", "https://unsafe.test", "*.broad.test", "safe.example"})
	want := []string{"agent.new-google.test", "safe.example"}
	if len(got) != len(want) {
		t.Fatalf("normalized domains=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalized domains=%v want=%v", got, want)
		}
	}
}

func TestSettingsRejectUnreviewableLearnedDomains(t *testing.T) {
	s := defaultSettings()
	s.TunnelLearnedDomains = []string{"*.googleapis.com"}
	if err := validateSettingsSecurity(s); err == nil {
		t.Fatal("wildcard learned domain must be rejected")
	}
}
