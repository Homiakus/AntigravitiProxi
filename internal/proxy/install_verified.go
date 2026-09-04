package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/atomicfile"
)

type managedProvenance struct {
	Version       string `json:"version"`
	Asset         string `json:"asset"`
	ReleaseDigest string `json:"release_digest"`
	BinarySHA256  string `json:"binary_sha256"`
	VerifiedAt    string `json:"verified_at"`
}

func (m *Manager) provenancePath() string {
	return filepath.Join(m.Config().Root, "bin", "sing-box.provenance.json")
}

// InstallVerified is the only installation path permitted for Agent Tunnel.
// It fails closed when GitHub release metadata does not provide a SHA-256
// digest, verifies the archive before extraction, records the installed binary
// hash, and re-verifies that hash before reusing a managed binary later.
func (m *Manager) InstallVerified(ctx context.Context) (string, error) {
	cfg := m.Config()
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
	managed := m.ManagedPath()
	want := assetNameFor(runtime.GOOS, runtime.GOARCH, cfg.SingBoxVer)

	if fileExists(managed) && versionContains(binaryVersion(ctx, managed), cfg.SingBoxVer) {
		if ok, detail := m.verifiedManagedBinary(managed, want, cfg.SingBoxVer); ok {
			m.log("info", "verified managed sing-box reusable: "+detail)
			return managed, nil
		}
		m.log("warn", "managed sing-box lacks valid provenance; reinstalling from verified release")
	}

	if err := os.MkdirAll(filepath.Dir(managed), 0o755); err != nil {
		return "", err
	}
	api := "https://api.github.com/repos/SagerNet/sing-box/releases/tags/v" + url.PathEscape(cfg.SingBoxVer)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch sing-box release metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub release API: %s", resp.Status)
	}
	var rel release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	var downloadURL, digest string
	for _, a := range rel.Assets {
		if a.Name == want {
			downloadURL, digest = a.BrowserDownloadURL, strings.TrimSpace(a.Digest)
			break
		}
	}
	if downloadURL == "" {
		return "", fmt.Errorf("release asset not found: %s", want)
	}
	if digest == "" || !strings.HasPrefix(strings.ToLower(digest), "sha256:") {
		return "", fmt.Errorf("refusing Agent Tunnel install: official release asset %s has no usable sha256 digest", want)
	}

	archive := filepath.Join(cfg.Root, ".verified-"+want)
	if err := downloadFile(ctx, downloadURL, archive, m.log); err != nil {
		return "", err
	}
	defer os.Remove(archive)
	gotArchive, err := sha256File(archive)
	if err != nil {
		return "", err
	}
	expectedArchive := strings.TrimPrefix(strings.ToLower(digest), "sha256:")
	if !strings.EqualFold(gotArchive, expectedArchive) {
		return "", fmt.Errorf("SHA-256 mismatch for %s: expected %s got %s", want, expectedArchive, gotArchive)
	}

	tmp := filepath.Join(cfg.Root, ".verified-extract")
	_ = os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o755); err != nil {
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
	binary, err := os.ReadFile(found)
	if err != nil {
		return "", err
	}
	if err := atomicfile.Write(managed, binary, 0o755); err != nil {
		return "", fmt.Errorf("install verified managed sing-box: %w", err)
	}
	binaryHash, err := sha256File(managed)
	if err != nil {
		return "", err
	}
	prov := managedProvenance{
		Version:       cfg.SingBoxVer,
		Asset:         want,
		ReleaseDigest: strings.ToLower(digest),
		BinarySHA256:  binaryHash,
		VerifiedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	pb, err := json.MarshalIndent(prov, "", "  ")
	if err != nil {
		return "", err
	}
	if err := atomicfile.Write(m.provenancePath(), append(pb, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("write sing-box provenance: %w", err)
	}
	m.log("info", "verified and installed managed sing-box "+cfg.SingBoxVer)
	return managed, nil
}

func (m *Manager) verifiedManagedBinary(path, asset, version string) (bool, string) {
	b, err := os.ReadFile(m.provenancePath())
	if err != nil {
		return false, "provenance missing"
	}
	var p managedProvenance
	if json.Unmarshal(b, &p) != nil || p.Version != version || p.Asset != asset || p.BinarySHA256 == "" || p.ReleaseDigest == "" {
		return false, "provenance invalid"
	}
	got, err := sha256File(path)
	if err != nil || !strings.EqualFold(got, p.BinarySHA256) {
		return false, "installed binary hash differs from verified provenance"
	}
	return true, fmt.Sprintf("version=%s sha256=%s", version, got)
}
