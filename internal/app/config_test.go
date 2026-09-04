package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateSettingsSecurityRejectsRemoteListeners(t *testing.T) {
	s := defaultSettings()
	for _, addr := range []string{"0.0.0.0:48765", "192.168.1.10:48765", "[::]:48765"} {
		s.Listen = addr
		if err := validateSettingsSecurity(s); err == nil {
			t.Fatalf("expected listen %q to be rejected", addr)
		}
	}

	s = defaultSettings()
	for _, host := range []string{"0.0.0.0", "192.168.1.10", "::"} {
		s.ProxyHost = host
		if err := validateSettingsSecurity(s); err == nil {
			t.Fatalf("expected proxy host %q to be rejected", host)
		}
	}
}

func TestValidateSettingsSecurityAcceptsLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:48765", "localhost:48765", "[::1]:48765"} {
		s := defaultSettings()
		s.Listen = addr
		if err := validateSettingsSecurity(s); err != nil {
			t.Fatalf("listen %q rejected: %v", addr, err)
		}
	}
}

func TestLoadSettingsSanitizesUnsafePersistedEndpoints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"listen":"0.0.0.0:48765","proxy_host":"192.168.1.5","proxy_port":7890}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := loadSettings(path)
	if s.Listen != "127.0.0.1:48765" {
		t.Fatalf("unsafe listen was not sanitized: %q", s.Listen)
	}
	if s.ProxyHost != "127.0.0.1" {
		t.Fatalf("unsafe proxy host was not sanitized: %q", s.ProxyHost)
	}
}
