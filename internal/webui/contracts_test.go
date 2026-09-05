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
		`Domain fallback`,
		`слабее process isolation`,
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
		`Подготовить Tunnel и запустить IDE`,
		`PolicyKit`,
		`Пароль не читается и не хранится`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("index.html is missing setup UX marker %q", want)
		}
	}

	for _, want := range []string{
		`function renderSetup()`,
		`async function prepareTunnelRoute()`,
		`candidates.length===1`,
		`await api('/api/actions/stop',{method:'POST'})`,
		`PolicyKit-диалог`,
		`function friendlyTunnelError`,
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("app.js is missing one-click setup contract marker %q", want)
		}
	}
}
