package consistency

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type riskRegister struct {
	Risks []struct {
		ID       string   `json:"id"`
		Status   string   `json:"status"`
		Controls []string `json:"controls"`
	} `json:"risks"`
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readRepoFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func requireAll(t *testing.T, name, text string, markers ...string) {
	t.Helper()
	for _, marker := range markers {
		if !strings.Contains(text, marker) {
			t.Errorf("%s is missing canonical marker %q", name, marker)
		}
	}
}

func forbidAll(t *testing.T, name, text string, markers ...string) {
	t.Helper()
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			t.Errorf("%s still contains stale contract %q", name, marker)
		}
	}
}

func TestCanonicalDocsMatchCurrentRoutingAndPrivilegeModel(t *testing.T) {
	root := repoRoot(t)

	readme := readRepoFile(t, root, "README.md")
	requireAll(t, "README.md", readme,
		"auto_redirect=false",
		"strict_route=true",
		"vpn-direct",
		"fixed-function internal helper",
		"PolicyKit",
		"GET /api/attestation",
		"ISOLATION-RELAXED",
	)
	forbidAll(t, "README.md", readme,
		"на Linux включён `auto_redirect`",
		"перезапустить приложение с нужными правами",
		"Linux: нужны `root` или подходящие capabilities",
		"agent-vpn outbound",
	)

	arch := readRepoFile(t, root, "docs/ARCHITECTURE.md")
	requireAll(t, "docs/ARCHITECTURE.md", arch,
		"auto_route=true + strict_route=true + auto_redirect=false",
		"fixed-function internal helper",
		"R-023 закрыт",
		"закрытый R-008",
		"GET /api/attestation",
	)
	forbidAll(t, "docs/ARCHITECTURE.md", arch,
		"На Linux используется `auto_route + auto_redirect`",
		"Открытый риск R-023",
		"Открытый риск R-008",
	)

	linuxDoc := readRepoFile(t, root, "docs/LINUX.md")
	requireAll(t, "docs/LINUX.md", linuxDoc,
		"auto_redirect=false",
		"fixed-function PolicyKit helper",
		"автоматически подготовит TUN/capabilities",
		"R-012 остаётся в состоянии `mitigating`",
		"Ручной fallback",
	)
	forbidAll(t, "docs/LINUX.md", linuxDoc,
		"автоматическое capability-preserving обновление запланировано",
		"Для полноценного **process-aware Agent Tunnel** выдайте capabilities только helper-бинарнику",
	)

	agentDoc := readRepoFile(t, root, "docs/AGENT_EXECUTION_FAILURE.md")
	requireAll(t, "docs/AGENT_EXECUTION_FAILURE.md", agentDoc,
		"Linux `strict_route=true`",
		"Linux `auto_redirect=false`",
		"fixed-function internal helper",
		"GET /api/attestation",
		"ISOLATION-RELAXED",
	)
	forbidAll(t, "docs/AGENT_EXECUTION_FAILURE.md", agentDoc,
		"Linux `auto_redirect=true`",
		"перезапустить AntigravitiProxi с нужными правами",
	)

	fmea := readRepoFile(t, root, "docs/ARCHITECTURE_FMEA.md")
	requireAll(t, "docs/ARCHITECTURE_FMEA.md", fmea,
		"auto_redirect=false",
		"fixed-function PolicyKit helper",
		"R-023 закрыт",
		"R-008 закрыт",
		"R-012 остаётся mitigating",
		"Windows minimal UAC helper",
	)
	forbidAll(t, "docs/ARCHITECTURE_FMEA.md", fmea,
		"Остаётся R-023: отсутствие digest сейчас должно стать fail-closed",
		"Архитектурно правильнее всё равно перейти к отдельному минимальному privileged helper",
		"Health model пока слишком бинарный",
		"Применение сетевых изменений не транзакционно",
	)

	plan := readRepoFile(t, root, "MASTER_PLAN.md")
	requireAll(t, "MASTER_PLAN.md", plan,
		"[x] Linux fixed-function one-shot PolicyKit helper",
		"[x] Linux capability loss after managed binary replacement is detected and repaired",
		"[x] Domain fallback visibly reported as `ISOLATION-RELAXED`",
		"[x] Race detector is part of CI",
		"[ ] Implement **Windows minimal UAC helper**",
	)

	tunnelSource := readRepoFile(t, root, "internal/proxy/tunnel.go")
	requireAll(t, "internal/proxy/tunnel.go", tunnelSource,
		"fixed-function PolicyKit helper",
		"tunInbound[\"auto_redirect\"] = false",
		"options.StrictRoute = true",
	)
	forbidAll(t, "internal/proxy/tunnel.go", tunnelSource,
		"For non-root operation grant managed sing-box",
	)
}

func TestPrivilegeFMEAMatchesImplementedLinuxControl(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "risks", "register.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reg riskRegister
	if err := json.Unmarshal(b, &reg); err != nil {
		t.Fatalf("parse risk register: %v", err)
	}

	byID := map[string]struct {
		Status   string
		Controls []string
	}{}
	for _, r := range reg.Risks {
		byID[r.ID] = struct {
			Status   string
			Controls []string
		}{r.Status, r.Controls}
	}

	r6, ok := byID["R-006"]
	if !ok {
		t.Fatal("R-006 missing")
	}
	joined6 := strings.Join(r6.Controls, " | ")
	for _, want := range []string{"fixed-function", "PolicyKit", "SHA-256", "password"} {
		if !strings.Contains(joined6, want) {
			t.Errorf("R-006 controls missing %q: %s", want, joined6)
		}
	}
	if r6.Status != "mitigating" {
		t.Errorf("R-006 status=%q want mitigating while Windows helper remains open", r6.Status)
	}

	r12, ok := byID["R-012"]
	if !ok {
		t.Fatal("R-012 missing")
	}
	joined12 := strings.Join(r12.Controls, " | ")
	for _, want := range []string{"automatically reapplies", "fixed-function PolicyKit", "post-setcap"} {
		if !strings.Contains(joined12, want) {
			t.Errorf("R-012 controls missing %q: %s", want, joined12)
		}
	}
	if r12.Status != "mitigating" {
		t.Errorf("R-012 status=%q want mitigating after automatic repair implementation", r12.Status)
	}
}
