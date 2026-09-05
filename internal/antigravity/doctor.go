package antigravity

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/diagnostics"
)

type AgentFinding struct {
	Severity string `json:"severity"`
	Kind     string `json:"kind"`
	Message  string `json:"message"`
	File     string `json:"file,omitempty"`
	Snippet  string `json:"snippet,omitempty"`
}

type AgentDoctorReport struct {
	LikelyCause   string         `json:"likely_cause"`
	Summary       string         `json:"summary"`
	FilesScanned  int            `json:"files_scanned"`
	Roots         []string       `json:"roots"`
	TrajectoryIDs []string       `json:"trajectory_ids,omitempty"`
	TraceIDs      []string       `json:"trace_ids,omitempty"`
	Findings      []AgentFinding `json:"findings"`
	NextSteps     []string       `json:"next_steps"`
}

type doctorPattern struct {
	needle   string
	kind     string
	severity string
	message  string
	priority int
}

var doctorPatterns = []doctorPattern{
	{"user location is not supported", "geo_eligibility", "error", "Backend rejected the model request because the user/request location is not supported.", 100},
	{"failed_precondition", "failed_precondition", "error", "Google backend returned FAILED_PRECONDITION. Inspect the nearby message; location/eligibility is a common cause.", 90},
	{"lightning dunning decision is deny", "account_eligibility", "error", "Backend account eligibility/billing decision denied the request.", 100},
	{"permission_denied", "account_permission", "error", "Backend denied the request for this account or credential.", 95},
	{"model_capacity_exhausted", "capacity", "warn", "Selected model/backend is out of capacity.", 80},
	{"resource_exhausted", "quota", "warn", "Quota or resource limit was exhausted.", 85},
	{"http 429", "quota", "warn", "HTTP 429 indicates quota/rate limiting.", 82},
	{"http 503", "backend_unavailable", "warn", "HTTP 503 indicates backend unavailability/capacity pressure.", 80},
	{"http 502", "backend_unavailable", "warn", "HTTP 502 indicates a transient backend/gateway failure.", 75},
	{"http 500", "backend_error", "error", "HTTP 500 came from the Antigravity/Google backend.", 85},
	{"\"status\":\"unknown\"", "backend_error", "error", "Backend returned UNKNOWN; this is not a local proxy syntax error.", 82},
	{"mcp error", "mcp", "error", "An MCP server/configuration error is terminating the agent.", 90},
	{"mcp_config", "mcp", "warn", "MCP configuration appears in the failing logs; test once with MCP disabled.", 60},
	{"pretooluse", "hook", "error", "A PreToolUse hook failed; a hook/extension can terminate every agent tool call.", 92},
	{"hook error", "hook", "error", "An agent hook failed during execution.", 88},
	{"extension host", "extension_host", "warn", "Extension-host instability appears in the logs.", 70},
	{"workspacestorage", "workspace_state", "warn", "Workspace state/storage appears in the failure path; a backed-up workspace-state reset may help.", 65},
	{"token refresh", "auth", "error", "OAuth token refresh failed during agent execution.", 88},
	{"invalid_grant", "auth", "error", "OAuth grant/session is invalid; sign-out and clean re-authentication is indicated.", 90},
	{"agent execution terminated due to error", "generic_termination", "warn", "The generic Agent execution failure was found, but this line alone does not identify the root cause.", 20},
}

var (
	trajectoryRE = regexp.MustCompile(`(?i)trajectory(?:\s+id|id)?\s*[:=]\s*([0-9a-f]{8}-[0-9a-f-]{20,})`)
	traceRE      = regexp.MustCompile(`(?i)trace(?:\s+id|id)?\s*[:=]\s*(0x[0-9a-f]+|[0-9a-f]{16,}|[0-9a-f]{8}-[0-9a-f-]{20,})`)
)

func AgentDoctor(ctx context.Context) AgentDoctorReport {
	report := AgentDoctorReport{
		LikelyCause: "unknown",
		Summary:     "No specific root cause found yet.",
		Findings:    []AgentFinding{},
	}
	roots := agentLogRoots()
	for _, r := range roots {
		if st, err := os.Stat(r); err == nil && st.IsDir() {
			report.Roots = append(report.Roots, displayPath(r))
		}
	}

	cutoff := time.Now().Add(-14 * 24 * time.Hour)
	type candidate struct {
		path string
		mod  time.Time
		size int64
	}
	var files []candidate

	for _, root := range roots {
		if ctx.Err() != nil {
			break
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return nil
			}
			if d.IsDir() {
				name := strings.ToLower(d.Name())
				if name == "node_modules" || name == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".log" && ext != ".txt" && ext != ".json" && ext != ".jsonl" {
				return nil
			}
			info, e := d.Info()
			if e != nil || info.ModTime().Before(cutoff) || info.Size() > 32<<20 {
				return nil
			}
			files = append(files, candidate{path: path, mod: info.ModTime(), size: info.Size()})
			return nil
		})
	}

	sort.Slice(files, func(i, j int) bool { return files[i].mod.After(files[j].mod) })
	if len(files) > 300 {
		files = files[:300]
	}

	seenFinding := map[string]bool{}
	bestPriority := 0
	bestKind := "unknown"

	for _, f := range files {
		if ctx.Err() != nil {
			break
		}
		b, err := readTail(f.path, 2<<20)
		if err != nil {
			continue
		}
		report.FilesScanned++
		text := string(b)
		lower := strings.ToLower(text)

		for _, m := range trajectoryRE.FindAllStringSubmatch(text, -1) {
			if len(m) > 1 {
				report.TrajectoryIDs = appendUnique(report.TrajectoryIDs, m[1])
			}
		}
		for _, m := range traceRE.FindAllStringSubmatch(text, -1) {
			if len(m) > 1 {
				report.TraceIDs = appendUnique(report.TraceIDs, m[1])
			}
		}

		for _, p := range doctorPatterns {
			idx := strings.Index(lower, p.needle)
			if idx < 0 {
				continue
			}
			key := p.kind + "|" + f.path
			if seenFinding[key] {
				continue
			}
			seenFinding[key] = true
			report.Findings = append(report.Findings, AgentFinding{
				Severity: p.severity,
				Kind:     p.kind,
				Message:  p.message,
				File:     displayPath(f.path),
				Snippet:  safeSnippet(text, idx, len(p.needle)),
			})
			if p.priority > bestPriority {
				bestPriority = p.priority
				bestKind = p.kind
			}
		}
	}

	report.LikelyCause = bestKind
	report.Summary, report.NextSteps = doctorAdvice(bestKind, len(report.Findings), report.FilesScanned)
	return report
}

func agentLogRoots() []string {
	home, _ := os.UserHomeDir()
	var roots []string
	if runtime.GOOS == "windows" {
		for _, base := range []string{os.Getenv("APPDATA"), os.Getenv("LOCALAPPDATA")} {
			if base == "" {
				continue
			}
			roots = append(roots,
				filepath.Join(base, "Antigravity"),
				filepath.Join(base, "Google", "Antigravity"),
			)
		}
	} else {
		cfg := os.Getenv("XDG_CONFIG_HOME")
		if cfg == "" && home != "" {
			cfg = filepath.Join(home, ".config")
		}
		if cfg != "" {
			roots = append(roots,
				filepath.Join(cfg, "Antigravity"),
				filepath.Join(cfg, "antigravity"),
				filepath.Join(cfg, "Google", "Antigravity"),
			)
		}
	}
	if home != "" {
		roots = append(roots,
			filepath.Join(home, ".antigravity"),
			filepath.Join(home, ".antigravity-ide"),
			filepath.Join(home, ".gemini", "antigravity-ide"),
			filepath.Join(home, ".gemini"),
		)
	}
	return uniqueStrings(roots)
}

func readTail(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := int64(0)
	if st.Size() > max {
		start = st.Size() - max
		if _, err = f.Seek(start, 0); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, st.Size()-start)
	_, err = f.Read(buf)
	return buf, err
}

func safeSnippet(text string, idx, n int) string {
	start := idx - 220
	if start < 0 {
		start = 0
	}
	end := idx + n + 360
	if end > len(text) {
		end = len(text)
	}
	s := text[start:end]
	s = diagnostics.Redact(s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 700 {
		s = s[:700] + "…"
	}
	return s
}

func displayPath(path string) string {
	home, _ := os.UserHomeDir()
	if home != "" {
		if rel, err := filepath.Rel(home, path); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			return filepath.Join("~", rel)
		}
	}
	return path
}

func appendUnique(in []string, value string) []string {
	for _, x := range in {
		if x == value {
			return in
		}
	}
	return append(in, value)
}

func uniqueStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, x := range in {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

func doctorAdvice(kind string, findings, scanned int) (string, []string) {
	base := []string{"Update Antigravity IDE to the latest official build before deeper troubleshooting."}
	switch kind {
	case "geo_eligibility", "failed_precondition":
		return "Authentication works, but the model-generation backend is rejecting the request at the geo/eligibility layer.", append(base,
			"Check the exact error/Trajectory ID in this report; changing the local proxy alone may not change a server-side account country association.",
			"Verify the Google account Country version and supported-country eligibility, then sign out/in after any approved account-country change.",
		)
	case "account_eligibility", "account_permission":
		return "The request reaches Google, but the account/credential is being denied by a backend eligibility or permission check.", append(base,
			"Capture the Trajectory/Trace ID and submit it through Antigravity feedback/support.",
			"A/B test the same machine/network with another eligible account if available; if only one account fails, this is account-side rather than routing.",
		)
	case "mcp":
		return "An MCP configuration/server is the strongest local cause found.", append(base,
			"Temporarily disable all MCP servers and retry a new empty project with a one-word prompt.",
			"Re-enable MCP servers one by one after the agent works.",
		)
	case "hook":
		return "A hook/extension is terminating agent execution before or during tool use.", append(base,
			"Disable the failing hook/extension and retry with a clean project.",
			"If the log names an extension, update or remove that extension before resetting broader state.",
		)
	case "auth":
		return "The IDE is signed in, but the execution path is failing token refresh/session validation.", append(base,
			"Sign out of Antigravity, fully close all Antigravity/language-server processes, then authenticate again.",
		)
	case "quota":
		return "The backend reports quota/rate exhaustion.", append(base, "Check the Antigravity Models/Quota screen and retry after the quota window resets.")
	case "capacity", "backend_unavailable", "backend_error":
		return "The request reaches the backend, which is returning a server/capacity error.", append(base,
			"Retry another model and a new empty conversation; preserve the Trajectory/Trace ID for support if it persists.",
		)
	case "workspace_state", "extension_host":
		return "Local workspace/extension state is implicated by the logs.", append(base,
			"Back up Antigravity state before clearing workspace/global cache; avoid deleting the whole profile until a targeted reset is tried.",
		)
	default:
		if findings == 0 {
			return fmt.Sprintf("No known root-cause signature was found in %d recent log files.", scanned), append(base,
				"Reproduce the failure once, then immediately run Agent Doctor again so the newest log entry is captured.",
				"Copy the visible Error ID / Trajectory ID from Antigravity if one is shown.",
			)
		}
		return "The generic termination was found, but no higher-confidence signature was present nearby.", append(base,
			"Reproduce once with all MCP servers disabled and a fresh empty project, then run Agent Doctor again.",
		)
	}
}
