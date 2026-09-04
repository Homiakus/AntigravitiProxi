package antigravity

import (
	"strings"
	"testing"
)

func TestFilteredEnvRemovesAllProxyCasesAndCloudCodeOverride(t *testing.T) {
	in := []string{
		"PATH=/bin",
		"HTTP_PROXY=a",
		"http_proxy=b",
		"HTTPS_PROXY=c",
		"NO_PROXY=d",
		"CLOUD_CODE_URL=https://daily-cloudcode-pa.googleapis.com",
		"cloud_code_url=https://bad.invalid",
		"KEEP=yes",
	}
	got := filteredEnv(in)
	if len(got) != 2 || got[0] != "PATH=/bin" || got[1] != "KEEP=yes" {
		t.Fatalf("unexpected env: %#v", got)
	}
}

func TestProcessProxyEnvPinsProductionCloudCode(t *testing.T) {
	got := processProxyEnv(
		[]string{"PATH=/bin", "CLOUD_CODE_URL=https://daily-cloudcode-pa.googleapis.com"},
		"http://127.0.0.1:7890",
		"socks5://127.0.0.1:7890",
	)
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "daily-cloudcode-pa.googleapis.com") {
		t.Fatalf("stale Cloud Code override survived: %s", joined)
	}
	if !strings.Contains(joined, "CLOUD_CODE_URL="+ProductionCloudCodeURL) {
		t.Fatalf("production Cloud Code URL missing: %s", joined)
	}
	if !strings.Contains(joined, "HTTPS_PROXY=http://127.0.0.1:7890") {
		t.Fatalf("HTTPS proxy missing: %s", joined)
	}
}

func TestRemoveHostsBlock(t *testing.T) {
	in := "127.0.0.1 localhost\n" + hostsStart + "\n1.2.3.4 daily-cloudcode-pa.googleapis.com\n" + hostsEnd + "\n8.8.8.8 x\n"
	got := removeBlock(in)
	if got != "127.0.0.1 localhost\n8.8.8.8 x\n" {
		t.Fatalf("unexpected: %q", got)
	}
}
