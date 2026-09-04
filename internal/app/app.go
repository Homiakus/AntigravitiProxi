package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/antigravity"
	"github.com/Homiakus/AntigravitiProxi/internal/diagnostics"
	"github.com/Homiakus/AntigravitiProxi/internal/platform"
	"github.com/Homiakus/AntigravitiProxi/internal/proxy"
	"github.com/Homiakus/AntigravitiProxi/internal/webui"
)

var targetDomains = []string{
	"antigravity.google",
	"oauth2.googleapis.com",
	"cloudcode-pa.googleapis.com",
	"daily-cloudcode-pa.googleapis.com",
}

type Server struct {
	mu           sync.Mutex
	root         string
	settingsPath string
	settings     Settings
	pm           *proxy.Manager
	events       *eventHub
	csrf         string
}

type Status struct {
	OS                   string               `json:"os"`
	Arch                 string               `json:"arch"`
	ProxyRunning         bool                 `json:"proxy_running"`
	ProxyURL             string               `json:"proxy_url"`
	SOCKSURL             string               `json:"socks_url"`
	SingBoxPath          string               `json:"sing_box_path,omitempty"`
	SingBoxVersion       string               `json:"sing_box_version,omitempty"`
	AntigravityPath      string               `json:"antigravity_path,omitempty"`
	AgentTunnelActive    bool                 `json:"agent_tunnel_active"`
	AgentTunnelSupported bool                 `json:"agent_tunnel_supported"`
	AgentTunnelHint      string               `json:"agent_tunnel_hint,omitempty"`
	Settings             Settings             `json:"settings"`
	Interfaces           []platform.Interface `json:"interfaces"`
}

func New() (*Server, error) {
	root, err := platform.ConfigDir()
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}

	settingsPath := filepath.Join(root, "config.json")
	settings := loadSettings(settingsPath)
	ifaces, _ := platform.Interfaces()
	if settings.VPNInterface == "" {
		for _, it := range ifaces {
			if it.LikelyVPN {
				settings.VPNInterface = it.Name
				break
			}
		}
	}

	hub := newEventHub()
	pm := proxy.New(proxy.Config{
		Root:         root,
		Host:         settings.ProxyHost,
		Port:         settings.ProxyPort,
		VPNInterface: settings.VPNInterface,
		DNSProvider:  settings.DNSProvider,
		SingBoxVer:   settings.SingBoxVer,
	}, hub.publish)

	token := make([]byte, 24)
	_, _ = rand.Read(token)

	s := &Server{
		root:         root,
		settingsPath: settingsPath,
		settings:     settings,
		pm:           pm,
		events:       hub,
		csrf:         hex.EncodeToString(token),
	}
	_ = saveSettings(settingsPath, settings)
	return s, nil
}

func (s *Server) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings
}

func (s *Server) ListenAddr() string { return s.Settings().Listen }
func (s *Server) AutoOpen() bool     { return s.Settings().AutoOpen }
func (s *Server) Root() string       { return s.root }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.HandleFunc("GET /api/diagnostics", s.handleDiagnostics)
	mux.HandleFunc("GET /api/agent-doctor", s.handleAgentDoctor)
	mux.HandleFunc("GET /api/logs", s.handleLogs)

	mux.HandleFunc("POST /api/config", s.requireCSRF(s.handleConfig))
	mux.HandleFunc("POST /api/actions/install", s.requireCSRF(s.handleInstall))
	mux.HandleFunc("POST /api/actions/start", s.requireCSRF(s.handleStart))
	mux.HandleFunc("POST /api/actions/stop", s.requireCSRF(s.handleStop))
	mux.HandleFunc("POST /api/actions/test", s.requireCSRF(s.handleTest))
	mux.HandleFunc("POST /api/actions/endpoint", s.requireCSRF(s.handleEndpoint))
	mux.HandleFunc("POST /api/actions/launch", s.requireCSRF(s.handleLaunch))
	mux.HandleFunc("POST /api/actions/hosts/enable", s.requireCSRF(s.handleHostsEnable))
	mux.HandleFunc("POST /api/actions/hosts/disable", s.requireCSRF(s.handleHostsDisable))
	mux.HandleFunc("POST /api/actions/safe", s.requireCSRF(s.handleSafeMode))
	mux.HandleFunc("POST /api/actions/tunnel/start", s.requireCSRF(s.handleTunnelStart))
	mux.HandleFunc("POST /api/actions/tunnel/stop", s.requireCSRF(s.handleTunnelStop))
	mux.HandleFunc("POST /api/actions/tunnel/launch", s.requireCSRF(s.handleTunnelLaunch))

	staticFS, err := fs.Sub(webui.FS, "static")
	if err != nil {
		panic(fmt.Sprintf("web UI embed filesystem: %v", err))
	}
	fileServer := http.FileServer(http.FS(staticFS))

	// FileServer already serves index.html for the directory root. Rewriting
	// "/" to "/index.html" would trigger FileServer's canonical redirect and
	// create a redirect loop.
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "agp_csrf",
			Value:    s.csrf,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
			Secure:   false,
			HttpOnly: false,
		})
		fileServer.ServeHTTP(w, r)
	})

	return s.securityHeaders(mux)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("agp_csrf")
		if err != nil || c.Value != s.csrf || r.Header.Get("X-AGP-CSRF") != s.csrf {
			http.Error(w, "CSRF validation failed", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func (s *Server) status(ctx context.Context) Status {
	ifaces, _ := platform.Interfaces()
	return Status{
		OS:                   runtime.GOOS,
		Arch:                 runtime.GOARCH,
		ProxyRunning:         s.pm.Running(),
		ProxyURL:             s.pm.HTTPProxyURL(),
		SOCKSURL:             "socks5://" + s.pm.SOCKSProxyAddr(),
		SingBoxPath:          s.pm.Find(),
		SingBoxVersion:       s.pm.Version(ctx),
		AntigravityPath:      antigravity.FindExecutable(),
		AgentTunnelActive:    s.pm.AgentTunnelActive(),
		AgentTunnelSupported: s.pm.AgentTunnelSupported(),
		AgentTunnelHint:      s.pm.AgentTunnelPrivilegeHint(),
		Settings:             s.Settings(),
		Interfaces:           ifaces,
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.status(r.Context()))
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	f, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch, cancel := s.events.subscribe()
	defer cancel()
	for {
		select {
		case e := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", eventJSON(e))
			f.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()
	d, err := diagnostics.Collect(ctx, targetDomains)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, d)
}

func (s *Server) handleAgentDoctor(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	report := antigravity.AgentDoctor(ctx)
	writeJSON(w, report)
}

func tail(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{
		"stdout": tail(s.pm.LogPath(), 200),
		"stderr": tail(s.pm.ErrPath(), 200),
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	var in Settings
	if err := decodeJSON(r, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	cur := s.settings
	if in.Listen != "" {
		cur.Listen = in.Listen
	}
	if in.ProxyHost != "" {
		cur.ProxyHost = in.ProxyHost
	}
	if in.ProxyPort > 0 && in.ProxyPort < 65536 {
		cur.ProxyPort = in.ProxyPort
	}
	cur.VPNInterface = in.VPNInterface
	if in.DNSProvider == "cloudflare" || in.DNSProvider == "google" {
		cur.DNSProvider = in.DNSProvider
	}
	if in.SingBoxVer != "" {
		cur.SingBoxVer = in.SingBoxVer
	}
	cur.AutoOpen = in.AutoOpen
	s.settings = cur
	s.mu.Unlock()

	s.pm.SetVPNInterface(cur.VPNInterface)
	s.pm.SetDNSProvider(cur.DNSProvider)
	_ = saveSettings(s.settingsPath, cur)
	s.events.publish("info", "configuration updated")
	writeJSON(w, map[string]any{"ok": true, "settings": cur})
}

func (s *Server) ensureSingBox(ctx context.Context) error {
	if s.pm.Find() != "" {
		return nil
	}
	_, err := s.pm.Install(ctx)
	return err
}

func (s *Server) handleInstall(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	p, err := s.pm.Install(ctx)
	if err != nil {
		s.events.publish("error", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "path": p, "version": s.pm.Version(ctx)})
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.ensureSingBox(ctx); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.pm.Start(ctx); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	time.Sleep(700 * time.Millisecond)
	writeJSON(w, map[string]any{"ok": s.pm.Running(), "proxy": s.pm.HTTPProxyURL(), "mode": "safe-proxy"})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if err := s.pm.Stop(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.events.publish("info", "proxy stop requested")
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleTest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	res := s.pm.Tests(ctx)
	for _, x := range res {
		lvl := "info"
		if !x.OK {
			lvl = "error"
		}
		s.events.publish(lvl, x.String())
	}
	writeJSON(w, res)
}

func (s *Server) handleEndpoint(w http.ResponseWriter, r *http.Request) {
	files, err := antigravity.ForceProductionEndpoint()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.events.publish("info", fmt.Sprintf("production endpoint applied to %d settings file(s)", len(files)))
	writeJSON(w, map[string]any{"ok": true, "files": files})
}

func (s *Server) handleLaunch(w http.ResponseWriter, r *http.Request) {
	if !s.pm.Running() {
		http.Error(w, "local proxy is not running", http.StatusConflict)
		return
	}
	if err := antigravity.LaunchWithProxy("", s.pm.HTTPProxyURL(), "socks5://"+s.pm.SOCKSProxyAddr()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.events.publish("info", "Antigravity launched with process-only proxy environment")
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleHostsEnable(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	ips := diagnostics.TrustedA(ctx, "daily-cloudcode-pa.googleapis.com")
	if len(ips) == 0 {
		http.Error(w, "pinned DoH returned no A record", http.StatusBadGateway)
		return
	}
	backup, err := antigravity.SetHostsOverride(
		"daily-cloudcode-pa.googleapis.com",
		ips[0],
		filepath.Join(s.root, "backups"),
	)
	if err != nil {
		http.Error(w, "hosts write failed (admin/root likely required): "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.events.publish("warn", "emergency hosts override enabled")
	writeJSON(w, map[string]any{"ok": true, "ip": ips[0], "backup": backup})
}

func (s *Server) handleHostsDisable(w http.ResponseWriter, r *http.Request) {
	if err := antigravity.RemoveHostsOverride(); err != nil {
		http.Error(w, "hosts write failed (admin/root likely required): "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.events.publish("info", "emergency hosts override removed")
	writeJSON(w, map[string]bool{"ok": true})
}

// SAFE MODE remains the low-impact first layer. It does not create a TUN and
// therefore does not change system routes. Use Agent Tunnel only when the IDE
// signs in successfully but the actual agent execution path still bypasses
// HTTP_PROXY.
func (s *Server) handleSafeMode(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()

	if err := s.ensureSingBox(ctx); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !s.pm.Running() {
		if err := s.pm.Start(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		time.Sleep(time.Second)
	}

	files, err := antigravity.ForceProductionEndpoint()
	if err != nil {
		s.events.publish("warn", "endpoint override: "+err.Error())
	}
	if err := antigravity.LaunchWithProxy("", s.pm.HTTPProxyURL(), "socks5://"+s.pm.SOCKSProxyAddr()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.events.publish("info", "SAFE MODE completed: proxy is process-only; system proxy untouched")
	writeJSON(w, map[string]any{"ok": true, "settings_files": files, "mode": "safe-proxy"})
}

func (s *Server) handleTunnelStart(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()

	if !s.pm.AgentTunnelSupported() {
		http.Error(w, s.pm.AgentTunnelPrivilegeHint(), http.StatusNotImplemented)
		return
	}
	if strings.TrimSpace(s.Settings().VPNInterface) == "" {
		http.Error(w, "Agent Tunnel requires selecting and saving a VPN interface first", http.StatusBadRequest)
		return
	}
	if err := s.ensureSingBox(ctx); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.pm.StopAndWait(ctx); err != nil {
		http.Error(w, "stop existing proxy before Agent Tunnel: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.pm.StartAgentTunnel(ctx); err != nil {
		s.events.publish("error", "Agent Tunnel start failed: "+err.Error())
		http.Error(w, err.Error()+"\n"+s.pm.AgentTunnelPrivilegeHint(), http.StatusInternalServerError)
		return
	}

	time.Sleep(1200 * time.Millisecond)
	if !s.pm.Running() {
		errText := tail(s.pm.ErrPath(), 80)
		if errText == "" {
			errText = "sing-box exited before the health check"
		}
		http.Error(w, errText+"\n"+s.pm.AgentTunnelPrivilegeHint(), http.StatusInternalServerError)
		return
	}

	s.events.publish("warn", "AGENT TUNNEL active: Antigravity traffic is process-routed through the selected VPN; unrelated apps use system-direct")
	writeJSON(w, map[string]any{
		"ok":              true,
		"mode":            "agent-tunnel",
		"active":          s.pm.AgentTunnelActive(),
		"vpn_interface":   s.Settings().VPNInterface,
		"privilege_hint":  s.pm.AgentTunnelPrivilegeHint(),
		"local_proxy":     s.pm.HTTPProxyURL(),
		"system_proxy_set": false,
	})
}

func (s *Server) handleTunnelStop(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.pm.StopAndWait(ctx); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.events.publish("info", "Agent Tunnel stopped; system routes released by sing-box")
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleTunnelLaunch(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()

	if !s.pm.AgentTunnelActive() {
		if !s.pm.AgentTunnelSupported() {
			http.Error(w, s.pm.AgentTunnelPrivilegeHint(), http.StatusNotImplemented)
			return
		}
		if strings.TrimSpace(s.Settings().VPNInterface) == "" {
			http.Error(w, "select and save a VPN interface before Agent Tunnel", http.StatusBadRequest)
			return
		}
		if err := s.ensureSingBox(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.pm.StopAndWait(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.pm.StartAgentTunnel(ctx); err != nil {
			http.Error(w, err.Error()+"\n"+s.pm.AgentTunnelPrivilegeHint(), http.StatusInternalServerError)
			return
		}
		time.Sleep(1200 * time.Millisecond)
	}

	files, err := antigravity.ForceProductionEndpoint()
	if err != nil {
		s.events.publish("warn", "endpoint override: "+err.Error())
	}

	// Keep process proxy variables as a belt-and-suspenders layer. Components
	// that honor them use the mixed proxy; components that ignore them are still
	// captured by the TUN process-routing layer.
	if err := antigravity.LaunchWithProxy("", s.pm.HTTPProxyURL(), "socks5://"+s.pm.SOCKSProxyAddr()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.events.publish("info", "Antigravity launched in AGENT TUNNEL mode")
	writeJSON(w, map[string]any{
		"ok":             true,
		"mode":           "agent-tunnel",
		"settings_files": files,
		"tunnel_active":  s.pm.AgentTunnelActive(),
	})
}

func (s *Server) Serve(ctx context.Context) error {
	addr := s.ListenAddr()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}()

	log.Printf("AntigravitiProxi UI: http://%s", addr)
	return srv.Serve(ln)
}
