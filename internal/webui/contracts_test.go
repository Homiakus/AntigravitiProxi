package webui

import (
	"strings"
	"testing"
)

func TestDomainFallbackControlIsWiredThroughUI(t *testing.T) {
	htmlBytes, err := FS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	jsBytes, err := FS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html := string(htmlBytes)
	js := string(jsBytes)

	for _, want := range []string{
		`id="tunnel-domain-fallback"`,
		`Разрешить fallback по домену`,
		`Fallback ослабляет изоляцию`,
		`id="policy-banner"`,
		`id="fallback-warning"`,
		`id="assurance-isolation"`,
		`id="assurance-isolation-detail"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("index.html is missing isolation contract marker %q", want)
		}
	}

	for _, want := range []string{
		`state.settings.tunnel_domain_fallback`,
		`tunnel_domain_fallback:!!$('#tunnel-domain-fallback')?.checked`,
		`v?.isolation||'inactive'`,
		`v?.isolation_detail||''`,
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("app.js is missing isolation contract marker %q", want)
		}
	}
}

func TestOneClickTunnelSetupIsVisibleAndWired(t *testing.T) {
	htmlBytes, err := FS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	jsBytes, err := FS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html := string(htmlBytes)
	js := string(jsBytes)

	for _, want := range []string{
		`id="setup-singbox"`,
		`id="setup-vpn"`,
		`id="setup-privileges"`,
		`id="setup-runtime"`,
		`Запустить proxy и Antigravity`,
		`Запустить proxy`,
		`Остановить proxy`,
		`127.0.0.1:7890`,
		`id="system-summary"`,
		`id="save-status"`,
		`id="diagnostics-panel"`,
		`id="diagnostics-ip"`,
		`id="diagnostics-details"`,
		`Локальный proxy запускается без TUN`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("index.html is missing setup UX marker %q", want)
		}
	}

	for _, want := range []string{
		`function renderSetup()`,
		`state.proxy_running?'ready':'auto'`,
		`TUN и системные proxy-настройки не изменяются.`,
		`async function refreshDiagnostics`,
		`api('/api/diagnostics')`,
		`let refreshInFlight = false`,
		`let assuranceInFlight = false`,
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("app.js is missing one-click setup contract marker %q", want)
		}
	}
}
