package app

import (
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestSettingsPatchCoversEveryPersistedSetting(t *testing.T) {
	settingsType := reflect.TypeOf(Settings{})
	patchType := reflect.TypeOf(settingsPatch{})
	if patchType.NumField() != settingsType.NumField() {
		t.Fatalf("settingsPatch fields=%d Settings fields=%d; every persisted setting needs an explicit API patch contract", patchType.NumField(), settingsType.NumField())
	}
	for i := 0; i < settingsType.NumField(); i++ {
		sf := settingsType.Field(i)
		pf, ok := patchType.FieldByName(sf.Name)
		if !ok {
			t.Fatalf("settingsPatch is missing Settings.%s", sf.Name)
		}
		if pf.Type.Kind() != reflect.Pointer || pf.Type.Elem() != sf.Type {
			t.Fatalf("settingsPatch.%s type=%v want pointer to %v", sf.Name, pf.Type, sf.Type)
		}
		if sf.Tag.Get("json") != pf.Tag.Get("json") {
			t.Fatalf("JSON contract drift for %s: Settings=%q patch=%q", sf.Name, sf.Tag.Get("json"), pf.Tag.Get("json"))
		}
	}
}

func TestTunnelSettingsContractIsExhaustive(t *testing.T) {
	typ := reflect.TypeOf(Settings{})
	var got []string
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if strings.HasPrefix(name, "Tunnel") {
			got = append(got, name)
		}
	}
	sort.Strings(got)
	want := []string{"TunnelDomainFallback", "TunnelStrictRoute"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tunnel Settings fields=%v want=%v; every new Tunnel* setting needs an explicit runtime contract test", got, want)
	}
}

func TestTunnelDomainFallbackFlowsToRuntimeOptions(t *testing.T) {
	for _, value := range []bool{false, true} {
		s := &Server{settings: defaultSettings()}
		s.settings.TunnelDomainFallback = value
		o := s.tunnelOptions()
		if o.DomainFallback != value {
			t.Fatalf("TunnelDomainFallback=%v produced DomainFallback=%v", value, o.DomainFallback)
		}
	}
}

func TestTunnelStrictRouteContractIsPlatformExplicit(t *testing.T) {
	for _, value := range []bool{false, true} {
		s := &Server{settings: defaultSettings()}
		s.settings.TunnelStrictRoute = value
		o := s.tunnelOptions()
		if runtime.GOOS == "linux" {
			if !o.StrictRoute {
				t.Fatalf("Linux must normalize StrictRoute=true regardless of persisted value=%v", value)
			}
			continue
		}
		if o.StrictRoute != value {
			t.Fatalf("%s TunnelStrictRoute=%v produced StrictRoute=%v", runtime.GOOS, value, o.StrictRoute)
		}
	}
}
