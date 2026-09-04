package antigravity

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const ProductionCloudCodeURL = "https://cloudcode-pa.googleapis.com"

var endpointRE = regexp.MustCompile(`(?m)"jetski\.cloudCodeUrl"\s*:\s*"[^"]*"`)

func SettingsCandidates() []string {
	home := effectiveUserHome()
	out := []string{}
	if runtime.GOOS == "windows" {
		app := os.Getenv("APPDATA")
		if app != "" {
			out = append(out,
				filepath.Join(app, "Antigravity", "User", "settings.json"),
				filepath.Join(app, "Google", "Antigravity", "User", "settings.json"),
			)
		}
	} else {
		cfg := effectiveConfigHome(home)
		if cfg != "" {
			out = append(out,
				filepath.Join(cfg, "Antigravity", "User", "settings.json"),
				filepath.Join(cfg, "antigravity", "User", "settings.json"),
				filepath.Join(cfg, "Google", "Antigravity", "User", "settings.json"),
				filepath.Join(cfg, "Antigravity IDE", "User", "settings.json"),
				filepath.Join(cfg, "antigravity-ide", "User", "settings.json"),
			)
		}
	}
	return out
}

func ForceProductionEndpoint() ([]string, error) {
	replacement := `"jetski.cloudCodeUrl": "` + ProductionCloudCodeURL + `"`
	changed := []string{}
	candidates := SettingsCandidates()
	found := false

	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		found = true
		raw := string(b)
		backup := fmt.Sprintf("%s.backup-%s", p, time.Now().Format("20060102-150405"))
		_ = os.WriteFile(backup, b, 0o600)

		var next string
		if endpointRE.MatchString(raw) {
			next = endpointRE.ReplaceAllString(raw, replacement)
		} else {
			idx := strings.Index(raw, "{")
			if idx < 0 {
				return changed, fmt.Errorf("settings file is not JSON-like: %s", p)
			}
			tail := raw[idx+1:]
			comma := ""
			if strings.TrimSpace(tail) != "}" && strings.TrimSpace(tail) != "" {
				comma = ","
			}
			next = raw[:idx+1] + "\n  " + replacement + comma + tail
		}

		if err = os.WriteFile(p, []byte(next), 0o600); err != nil {
			return changed, err
		}
		changed = append(changed, p)
	}

	if !found && len(candidates) > 0 {
		p := candidates[0]
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return nil, err
		}
		raw := "{\n  " + replacement + "\n}\n"
		if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
			return nil, err
		}
		changed = append(changed, p)
	}
	return changed, nil
}

func FindExecutable() string {
	names := []string{"antigravity", "antigravity-ide", "antigravity-desktop"}
	if runtime.GOOS == "windows" {
		names = []string{"Antigravity.exe", "antigravity.exe"}
	}
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}

	home := effectiveUserHome()
	var candidates []string
	if runtime.GOOS == "windows" {
		local := os.Getenv("LOCALAPPDATA")
		pf := os.Getenv("ProgramFiles")
		candidates = []string{
			filepath.Join(local, "Programs", "Antigravity", "Antigravity.exe"),
			filepath.Join(local, "Antigravity", "Antigravity.exe"),
			filepath.Join(pf, "Antigravity", "Antigravity.exe"),
		}
	} else {
		candidates = []string{
			"/usr/bin/antigravity",
			"/usr/bin/antigravity-ide",
			"/usr/local/bin/antigravity",
			"/usr/local/bin/antigravity-ide",
			"/opt/Antigravity/antigravity",
			"/opt/antigravity/antigravity",
			"/opt/antigravity/Antigravity",
			"/opt/antigravity-ide/Antigravity-IDE/bin/antigravity-ide",
			"/opt/antigravity-ide/Antigravity-IDE/antigravity-ide",
			filepath.Join(home, ".local", "bin", "antigravity"),
			filepath.Join(home, ".local", "bin", "antigravity-ide"),
			filepath.Join(home, ".local", "opt", "antigravity", "antigravity"),
			filepath.Join(home, ".local", "opt", "antigravity-ide", "Antigravity-IDE", "bin", "antigravity-ide"),
		}
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// LaunchWithProxy starts Antigravity with a process-scoped proxy environment.
// It also removes any inherited CLOUD_CODE_URL first and pins the child process
// to the production Cloud Code endpoint. A stale user/system CLOUD_CODE_URL can
// otherwise override jetski.cloudCodeUrl and make authentication succeed while
// the agent executor still talks to the wrong backend.
func LaunchWithProxy(exe, httpProxy, socksProxy string) error {
	if exe == "" {
		exe = FindExecutable()
	}
	if exe == "" {
		return errors.New("Antigravity executable not found")
	}

	cmd := exec.Command(exe)
	env := processProxyEnv(os.Environ(), httpProxy, socksProxy)
	preparedEnv, err := prepareLaunchCommand(cmd, env)
	if err != nil {
		return err
	}
	cmd.Env = preparedEnv
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func processProxyEnv(base []string, httpProxy, socksProxy string) []string {
	env := filteredEnv(base)
	no := "localhost,127.0.0.1,::1"
	return append(env,
		"HTTP_PROXY="+httpProxy,
		"HTTPS_PROXY="+httpProxy,
		"ALL_PROXY="+socksProxy,
		"NO_PROXY="+no,
		"http_proxy="+httpProxy,
		"https_proxy="+httpProxy,
		"all_proxy="+socksProxy,
		"no_proxy="+no,
		"CLOUD_CODE_URL="+ProductionCloudCodeURL,
	)
}

func filteredEnv(in []string) []string {
	keys := map[string]bool{
		"HTTP_PROXY":     true,
		"HTTPS_PROXY":    true,
		"ALL_PROXY":      true,
		"NO_PROXY":       true,
		"CLOUD_CODE_URL": true,
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		p := strings.SplitN(v, "=", 2)
		if len(p) == 2 && keys[strings.ToUpper(p[0])] {
			continue
		}
		out = append(out, v)
	}
	return out
}
