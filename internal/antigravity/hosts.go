package antigravity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/atomicfile"
	"github.com/Homiakus/AntigravitiProxi/internal/platform"
)

const hostsStart = "# >>> ANTIGRAVITI-PROXI >>>"
const hostsEnd = "# <<< ANTIGRAVITI-PROXI <<<"

const hostsOverrideTTL = 30 * time.Minute

type hostsOverrideMetadata struct {
	Domain    string    `json:"domain"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func hostsMetadataPath(backupDir string) string {
	return filepath.Join(backupDir, "hosts-override.json")
}

func SetHostsOverride(domain, ip, backupDir string) (string, error) {
	p := platform.HostsPath()
	b, e := os.ReadFile(p)
	if e != nil {
		return "", e
	}
	if e = os.MkdirAll(backupDir, 0o755); e != nil {
		return "", e
	}
	backup := fmt.Sprintf("%s/hosts-%s.bak", strings.TrimRight(backupDir, "/\\"), time.Now().Format("20060102-150405"))
	if e = os.WriteFile(backup, b, 0o600); e != nil {
		return "", e
	}
	raw := removeBlock(string(b))
	raw = strings.TrimRight(raw, "\r\n") + "\n" + hostsStart + "\n" + ip + "    " + domain + "\n" + hostsEnd + "\n"
	if e = atomicfile.Write(p, []byte(raw), 0o644); e != nil {
		return "", e
	}
	now := time.Now().UTC()
	metadata := hostsOverrideMetadata{Domain: domain, IP: ip, CreatedAt: now, ExpiresAt: now.Add(hostsOverrideTTL)}
	mb, e := json.MarshalIndent(metadata, "", "  ")
	if e != nil {
		return "", e
	}
	if e = atomicfile.Write(hostsMetadataPath(backupDir), append(mb, '\n'), 0o600); e != nil {
		return "", e
	}
	return backup, nil
}
func RemoveHostsOverride() error {
	p := platform.HostsPath()
	b, e := os.ReadFile(p)
	if e != nil {
		return e
	}
	return atomicfile.Write(p, []byte(removeBlock(string(b))), 0o644)
}

// ExpireHostsOverride removes only the marker-scoped override when its
// ownership metadata proves it is ours and its TTL has elapsed. It never
// rewrites an unrecognised hosts file and returns false when no metadata exists.
func ExpireHostsOverride(backupDir string, now time.Time) (bool, error) {
	path := hostsMetadataPath(backupDir)
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var metadata hostsOverrideMetadata
	if err := json.Unmarshal(b, &metadata); err != nil || metadata.Domain == "" || metadata.IP == "" || metadata.ExpiresAt.IsZero() {
		return false, fmt.Errorf("invalid hosts override metadata")
	}
	if now.Before(metadata.ExpiresAt) {
		return false, nil
	}
	hostsPath := platform.HostsPath()
	hosts, err := os.ReadFile(hostsPath)
	if err != nil {
		return false, err
	}
	if !hasOwnedHostsLine(string(hosts), metadata) {
		return false, fmt.Errorf("hosts override ownership cannot be proven")
	}
	if err := atomicfile.Write(hostsPath, []byte(removeBlock(string(hosts))), 0o644); err != nil {
		return false, err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return true, nil
}

func hasOwnedHostsLine(hosts string, metadata hostsOverrideMetadata) bool {
	start := strings.Index(hosts, hostsStart)
	end := strings.Index(hosts, hostsEnd)
	if start < 0 || end < start {
		return false
	}
	for _, line := range strings.Split(hosts[start:end], "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == metadata.IP && fields[1] == metadata.Domain {
			return true
		}
	}
	return false
}
func removeBlock(s string) string {
	re := regexp.MustCompile(`(?s)` + regexp.QuoteMeta(hostsStart) + `.*?` + regexp.QuoteMeta(hostsEnd) + `\s*`)
	return re.ReplaceAllString(s, "")
}
