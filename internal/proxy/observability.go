package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/atomicfile"
)

const (
	singBoxAPIHost = "127.0.0.1"
	singBoxAPIPort = 48766
)

type RuntimeConnection struct {
	Source      string `json:"source,omitempty"`
	Process     string `json:"process,omitempty"`
	Outbound    string `json:"outbound,omitempty"`
	Destination string `json:"destination,omitempty"`
	Inbound     string `json:"inbound,omitempty"`
	Network     string `json:"network,omitempty"`
}

type RouteAttestation struct {
	Available       bool                `json:"available"`
	ObservedAt      time.Time           `json:"observed_at"`
	Connections     []RuntimeConnection `json:"connections,omitempty"`
	AgentObserved   int                 `json:"agent_observed"`
	AgentVPNDirect  int                 `json:"agent_vpn_direct"`
	AgentUnexpected int                 `json:"agent_unexpected"`
	UnknownHelpers  []string            `json:"unknown_helpers,omitempty"`
	Detail          string              `json:"detail"`
}

func apiSecretPath(root string) string {
	return filepath.Join(root, "sing-box-api-secret")
}

func ensureAPISecret(root string) (string, error) {
	path := apiSecretPath(root)
	if b, err := os.ReadFile(path); err == nil {
		secret := strings.TrimSpace(string(b))
		if len(secret) >= 32 {
			return secret, nil
		}
		return "", errors.New("existing sing-box API secret is unexpectedly short")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate sing-box API secret: %w", err)
	}
	secret := hex.EncodeToString(raw)
	if err := atomicfile.Write(path, []byte(secret+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("persist sing-box API secret: %w", err)
	}
	return secret, nil
}

func (m *Manager) APIAddr() string {
	return net.JoinHostPort(singBoxAPIHost, fmt.Sprint(singBoxAPIPort))
}

func (m *Manager) apiSecret() (string, error) {
	b, err := os.ReadFile(apiSecretPath(m.Config().Root))
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(b))
	if len(secret) < 32 {
		return "", errors.New("sing-box API secret is missing or invalid")
	}
	return secret, nil
}

// RuntimeConnections asks the running, pinned sing-box process for its own
// connection-tracker snapshot. We deliberately invoke the same managed binary
// as a client instead of importing sing-box's unstable daemon protobuf package.
// In non-terminal mode `sing-box api connection list` emits tab-separated rows,
// which is a stable CLI contract in 1.14. Source endpoint evidence is retained
// so a higher-level attestor can correlate a live connection with OS socket/PID
// ownership instead of trusting only a process-path string.
func (m *Manager) RuntimeConnections(ctx context.Context) ([]RuntimeConnection, error) {
	if !m.ManagedRunning() || m.Mode() != ModeAgentTunnel {
		return nil, errors.New("Agent Tunnel is not running")
	}
	binary := m.Find()
	if binary == "" {
		return nil, errors.New("managed sing-box executable not found")
	}
	secret, err := m.apiSecret()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, binary,
		"api",
		"--url", "http://"+m.APIAddr(),
		"--secret", secret,
		"connection", "list",
		"--columns", "source,process,outbound,destination,inbound,network",
	)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("sing-box API connection snapshot failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("sing-box API connection snapshot failed: %w", err)
	}
	return parseRuntimeConnections(string(out))
}

func parseRuntimeConnections(raw string) ([]RuntimeConnection, error) {
	var out []RuntimeConnection
	for lineNo, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cells := strings.Split(line, "\t")
		if len(cells) != 6 {
			return nil, fmt.Errorf("unexpected sing-box API row %d: got %d columns", lineNo+1, len(cells))
		}
		clean := func(v string) string {
			if v == "-" {
				return ""
			}
			return v
		}
		out = append(out, RuntimeConnection{
			Source:      clean(cells[0]),
			Process:     clean(cells[1]),
			Outbound:    clean(cells[2]),
			Destination: clean(cells[3]),
			Inbound:     clean(cells[4]),
			Network:     clean(cells[5]),
		})
	}
	return out, nil
}

// AttestAgentRoutes proves the runtime routing decision for live Antigravity
// connections. This is stronger than static JSON validation: sing-box itself
// reports the source endpoint, process path and chosen outbound from its
// connection tracker. Source endpoint evidence is intentionally preserved for
// the next assurance layer that maps sockets back to concrete PIDs.
func (m *Manager) AttestAgentRoutes(ctx context.Context) RouteAttestation {
	r := RouteAttestation{ObservedAt: time.Now().UTC()}
	connections, err := m.RuntimeConnections(ctx)
	if err != nil {
		r.Detail = err.Error()
		return r
	}
	r.Available = true
	r.Connections = connections
	seenUnknown := map[string]bool{}
	for _, c := range connections {
		if !looksLikeAntigravityProcess(c.Process) {
			continue
		}
		r.AgentObserved++
		if c.Outbound == "vpn-direct" {
			r.AgentVPNDirect++
		} else {
			r.AgentUnexpected++
		}
		if !knownAntigravityProcessPath(c.Process) && c.Process != "" && !seenUnknown[c.Process] {
			seenUnknown[c.Process] = true
			r.UnknownHelpers = append(r.UnknownHelpers, c.Process)
		}
	}
	if r.AgentObserved == 0 {
		r.Detail = "sing-box API is healthy, but no live Antigravity connection is currently observable"
	} else if r.AgentUnexpected > 0 {
		r.Detail = fmt.Sprintf("%d/%d live Antigravity connections are not using vpn-direct", r.AgentUnexpected, r.AgentObserved)
	} else {
		r.Detail = fmt.Sprintf("all %d observed Antigravity connections use vpn-direct", r.AgentObserved)
	}
	return r
}

func looksLikeAntigravityProcess(path string) bool {
	p := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	return strings.Contains(p, "antigravity") || strings.Contains(p, "language_server") || strings.Contains(p, "language-server") || strings.HasSuffix(p, "/agy") || strings.HasSuffix(p, "/agy.exe")
}

func knownAntigravityProcessPath(path string) bool {
	p := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	if strings.Contains(p, "antigravity") || strings.Contains(p, "language_server") || strings.Contains(p, "language-server") {
		return true
	}
	base := p
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	switch base {
	case "agy", "agy.exe":
		return true
	default:
		return false
	}
}
