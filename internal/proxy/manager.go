package proxy

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const DefaultSingBoxVersion = "1.14.0"

type Mode string

const (
	ModeOff         Mode = "off"
	ModeProxy       Mode = "proxy"
	ModeAgentTunnel Mode = "agent-tunnel"
)

type Logger func(level, message string)

type Config struct {
	Root         string
	Host         string
	Port         int
	VPNInterface string
	DNSProvider  string
	SingBoxVer   string
}

type Manager struct {
	mu     sync.Mutex
	cfg    Config
	cmd    *exec.Cmd
	logger Logger
	mode   Mode
}

type release struct {
	Assets []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Digest             string `json:"digest"`
	} `json:"assets"`
}

func New(cfg Config, logger Logger) *Manager {
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}
	if cfg.Port == 0 {
		cfg.Port = 7890
	}
	if cfg.DNSProvider == "" {
		cfg.DNSProvider = "cloudflare"
	}
	if cfg.SingBoxVer == "" {
		cfg.SingBoxVer = DefaultSingBoxVersion
	}
	return &Manager{cfg: cfg, logger: logger, mode: ModeOff}
}

func (m *Manager) log(level, msg string) {
	if m.logger != nil {
		m.logger(level, msg)
	}
}

func (m *Manager) SetVPNInterface(name string) {
	m.mu.Lock()
	m.cfg.VPNInterface = name
	m.mu.Unlock()
}

func (m *Manager) SetDNSProvider(name string) {
	m.mu.Lock()
	m.cfg.DNSProvider = name
	m.mu.Unlock()
}

func (m *Manager) SetSingBoxVersion(version string) {
	m.mu.Lock()
	if version != "" {
		m.cfg.SingBoxVer = version
	}
	m.mu.Unlock()
}

func (m *Manager) Config() Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

func (m *Manager) Mode() Mode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

func (m *Manager) ManagedRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cmd != nil && m.cmd.Process != nil
}

func (m *Manager) TunnelRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode == ModeAgentTunnel && m.cmd != nil && m.cmd.Process != nil
}

func (m *Manager) ConfigPath() string {
	return filepath.Join(m.cfg.Root, "sing-box.json")
}

func (m *Manager) TunnelConfigPath() string {
	return filepath.Join(m.cfg.Root, "sing-box-agent-tunnel.json")
}

func (m *Manager) LogPath() string {
	return filepath.Join(m.cfg.Root, "sing-box.log")
}

func (m *Manager) ErrPath() string {
	return filepath.Join(m.cfg.Root, "sing-box-error.log")
}

func executableName() string {
	if runtime.GOOS == "windows" {
		return "sing-box.exe"
	}
	return "sing-box"
}

func (m *Manager) ManagedPath() string {
	return filepath.Join(m.cfg.Root, "bin", executableName())
}

func (m *Manager) Find() string {
	if p := m.ManagedPath(); fileExists(p) {
		return p
	}
	if p, err := exec.LookPath(executableName()); err == nil {
		return p
	}
	if p, err := exec.LookPath("sing-box"); err == nil {
		return p
	}
	return ""
}

func binaryVersion(ctx context.Context, path string) string {
	if path == "" {
		return ""
	}
	out, err := exec.CommandContext(ctx, path, "version").CombinedOutput()
	if err != nil {
		return ""
	}
	first := strings.TrimSpace(string(out))
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	return first
}

func versionContains(versionOutput, want string) bool {
	if versionOutput == "" || want == "" {
		return false
	}
	return strings.Contains(versionOutput, " "+want) ||
		strings.HasSuffix(versionOutput, want) ||
		strings.Contains(versionOutput, "v"+want)
}

func (m *Manager) Version(ctx context.Context) string {
	return binaryVersion(ctx, m.Find())
}

// Install guarantees that the managed sing-box binary matches the configured
// version. This is intentionally deterministic: an older binary already in
// PATH must not silently be used for Agent Tunnel features introduced later.
func (m *Manager) Install(ctx context.Context) (string, error) {
	cfg := m.Config()
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	managed := m.ManagedPath()
	if fileExists(managed) {
		got := binaryVersion(ctx, managed)
		if versionContains(got, cfg.SingBoxVer) {
			m.log("info", "managed sing-box already available: "+got)
			return managed, nil
		}
		m.log("warn", fmt.Sprintf("managed sing-box version mismatch: have %q, want %s; upgrading", got, cfg.SingBoxVer))
	}

	// Reuse a system binary only when it already matches the exact requested
	// release. Otherwise install the pinned managed release below.
	for _, name := range []string{executableName(), "sing-box"} {
		if p, err := exec.LookPath(name); err == nil && p != managed {
			got := binaryVersion(ctx, p)
			if versionContains(got, cfg.SingBoxVer) {
				m.log("info", "matching system sing-box available: "+p)
				return p, nil
			}
		}
	}

	if err := os.MkdirAll(filepath.Join(cfg.Root, "bin"), 0o755); err != nil {
		return "", err
	}

	ver := cfg.SingBoxVer
	api := "https://api.github.com/repos/SagerNet/sing-box/releases/tags/v" + url.PathEscape(ver)
	m.log("info", "fetching official sing-box release metadata v"+ver)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub release API: %s", resp.Status)
	}

	var rel release
	if err = json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	want := assetNameFor(runtime.GOOS, runtime.GOARCH, ver)
	var downloadURL, digest string
	for _, a := range rel.Assets {
		if a.Name == want {
			downloadURL, digest = a.BrowserDownloadURL, a.Digest
			break
		}
	}
	if downloadURL == "" {
		return "", fmt.Errorf("release asset not found: %s", want)
	}

	archive := filepath.Join(cfg.Root, want)
	if err = downloadFile(ctx, downloadURL, archive, m.log); err != nil {
		return "", err
	}
	defer os.Remove(archive)

	if digest != "" {
		got, hashErr := sha256File(archive)
		if hashErr != nil {
			return "", hashErr
		}
		expected := strings.TrimPrefix(strings.ToLower(digest), "sha256:")
		if !strings.EqualFold(got, expected) {
			return "", fmt.Errorf("SHA-256 mismatch: expected %s got %s", expected, got)
		}
		m.log("info", "SHA-256 verified against GitHub release metadata")
	} else {
		m.log("warn", "release metadata has no digest; archive authenticity could not be pinned")
	}

	tmp := filepath.Join(cfg.Root, "extract")
	_ = os.RemoveAll(tmp)
	if err = os.MkdirAll(tmp, 0o755); err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	if strings.HasSuffix(want, ".zip") {
		err = extractZip(archive, tmp)
	} else {
		err = extractTarGz(archive, tmp)
	}
	if err != nil {
		return "", err
	}

	found, err := findFile(tmp, executableName())
	if err != nil {
		return "", err
	}
	if err = copyFile(found, managed, 0o755); err != nil {
		return "", err
	}
	m.log("info", "installed managed sing-box: "+managed)
	return managed, nil
}

func assetNameFor(goos, goarch, ver string) string {
	if goos == "windows" {
		return fmt.Sprintf("sing-box-%s-windows-%s.zip", ver, goarch)
	}
	return fmt.Sprintf("sing-box-%s-linux-%s.tar.gz", ver, goarch)
}

func (m *Manager) WriteConfig() error {
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()
	return writeConfig(cfg, m.ConfigPath())
}

func writeConfig(cfg Config, path string) error {
	if err := os.MkdirAll(cfg.Root, 0o755); err != nil {
		return err
	}
	dnsIP, dnsName := "1.1.1.1", "cloudflare-dns.com"
	if strings.EqualFold(cfg.DNSProvider, "google") {
		dnsIP, dnsName = "8.8.8.8", "dns.google"
	}

	dnsServer := map[string]any{
		"type":        "https",
		"tag":         "secure-doh",
		"server":      dnsIP,
		"server_port": 443,
		"path":        "/dns-query",
		"tls": map[string]any{
			"enabled":     true,
			"server_name": dnsName,
		},
	}
	direct := map[string]any{
		"type": "direct",
		"tag":  "vpn-direct",
		"domain_resolver": map[string]any{
			"server":   "secure-doh",
			"strategy": "ipv4_only",
		},
	}
	if cfg.VPNInterface != "" {
		dnsServer["bind_interface"] = cfg.VPNInterface
		direct["bind_interface"] = cfg.VPNInterface
	}

	doc := map[string]any{
		"log": map[string]any{"level": "info", "timestamp": true},
		"dns": map[string]any{
			"servers":  []any{dnsServer},
			"final":    "secure-doh",
			"strategy": "ipv4_only",
		},
		"inbounds": []any{
			map[string]any{
				"type":        "mixed",
				"tag":         "local-mixed",
				"listen":      cfg.Host,
				"listen_port": cfg.Port,
			},
		},
		"outbounds": []any{direct},
		"route": map[string]any{
			"default_domain_resolver": map[string]any{
				"server":   "secure-doh",
				"strategy": "ipv4_only",
			},
			"final": "vpn-direct",
		},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func (m *Manager) writeConfigLocked() error {
	return writeConfig(m.cfg, m.ConfigPath())
}

func (m *Manager) startLocked(ctx context.Context, configPath string, mode Mode, description string) error {
	if m.cmd != nil && m.cmd.Process != nil {
		return fmt.Errorf("sing-box already started by this process in %s mode", m.mode)
	}
	p := m.Find()
	if p == "" {
		return errors.New("sing-box not installed")
	}

	check := exec.CommandContext(ctx, p, "check", "-c", configPath)
	if out, err := check.CombinedOutput(); err != nil {
		return fmt.Errorf("sing-box config check failed: %v: %s", err, strings.TrimSpace(string(out)))
	}

	logf, err := os.OpenFile(m.LogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	errF, err := os.OpenFile(m.ErrPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		_ = logf.Close()
		return err
	}

	cmd := exec.Command(p, "run", "-c", configPath)
	cmd.Stdout, cmd.Stderr = logf, errF
	if err = cmd.Start(); err != nil {
		_ = logf.Close()
		_ = errF.Close()
		return err
	}
	m.cmd = cmd
	m.mode = mode

	go func() {
		err := cmd.Wait()
		_ = logf.Close()
		_ = errF.Close()
		m.mu.Lock()
		if m.cmd == cmd {
			m.cmd = nil
			m.mode = ModeOff
		}
		m.mu.Unlock()
		if err != nil {
			m.log("error", "sing-box exited: "+err.Error())
		} else {
			m.log("info", "sing-box stopped")
		}
	}()
	m.log("info", description)
	return nil
}

func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.writeConfigLocked(); err != nil {
		return err
	}
	return m.startLocked(ctx, m.ConfigPath(), ModeProxy,
		fmt.Sprintf("local mixed proxy started at %s:%d", m.cfg.Host, m.cfg.Port))
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	cmd := m.cmd
	m.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

// Running reports whether the local mixed diagnostic port is reachable. Both
// proxy mode and Agent Tunnel mode expose this port.
func (m *Manager) Running() bool {
	cfg := m.Config()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port)), 350*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (m *Manager) HTTPProxyURL() string {
	cfg := m.Config()
	return fmt.Sprintf("http://%s:%d", cfg.Host, cfg.Port)
}

func (m *Manager) SOCKSProxyAddr() string {
	cfg := m.Config()
	return net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port))
}

func downloadFile(ctx context.Context, rawURL, path string, logger Logger) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	resp, err := (&http.Client{Timeout: 3 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: %s", resp.Status)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if logger != nil {
		logger("info", "downloading "+rawURL)
	}
	_, err = io.Copy(f, resp.Body)
	return err
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err = os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func findFile(root, name string) (string, error) {
	var found string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == name {
			found = path
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("%s not found in archive", name)
	}
	return found, nil
}

func extractZip(src, dst string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		path := filepath.Join(dst, filepath.Clean(f.Name))
		if !strings.HasPrefix(path, filepath.Clean(dst)+string(os.PathSeparator)) {
			return errors.New("zip path traversal")
		}
		if f.FileInfo().IsDir() {
			if err = os.MkdirAll(path, 0o755); err != nil {
				return err
			}
			continue
		}
		if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		rc, openErr := f.Open()
		if openErr != nil {
			return openErr
		}
		out, createErr := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, f.Mode())
		if createErr != nil {
			_ = rc.Close()
			return createErr
		}
		_, copyErr := io.Copy(out, rc)
		_ = rc.Close()
		_ = out.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

func extractTarGz(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, nextErr := tr.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return nextErr
		}
		path := filepath.Join(dst, filepath.Clean(h.Name))
		if !strings.HasPrefix(path, filepath.Clean(dst)+string(os.PathSeparator)) {
			return errors.New("tar path traversal")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(path, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			out, createErr := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(h.Mode))
			if createErr != nil {
				return createErr
			}
			_, copyErr := io.Copy(out, tr)
			_ = out.Close()
			if copyErr != nil {
				return copyErr
			}
		}
	}
	return nil
}
