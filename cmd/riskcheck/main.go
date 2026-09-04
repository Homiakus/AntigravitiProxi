package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type register struct {
	SchemaVersion int          `json:"schema_version"`
	Method        string       `json:"method"`
	ReviewPolicy  reviewPolicy `json:"review_policy"`
	Risks         []risk       `json:"risks"`
}

type reviewPolicy struct {
	Cadence                   string `json:"cadence"`
	HighRPNThreshold          int    `json:"high_rpn_threshold"`
	CriticalSeverityThreshold int    `json:"critical_severity_threshold"`
	ReleaseRule               string `json:"release_rule"`
}

type risk struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Component        string   `json:"component"`
	FailureMode      string   `json:"failure_mode"`
	Effect           string   `json:"effect"`
	Cause            string   `json:"cause"`
	Controls         []string `json:"controls"`
	InitialRPN       int      `json:"initial_rpn"`
	Severity         int      `json:"severity"`
	Occurrence       int      `json:"occurrence"`
	Detection        int      `json:"detection"`
	RPN              int      `json:"rpn"`
	Status           string   `json:"status"`
	Owner            string   `json:"owner"`
	TargetMilestone  string   `json:"target_milestone"`
	Mitigation       string   `json:"mitigation"`
	Verification     string   `json:"verification"`
	PlanRefs         []string `json:"plan_refs"`
	LastReviewed     string   `json:"last_reviewed"`
	AcceptanceReason string   `json:"acceptance_reason,omitempty"`
}

var riskIDRE = regexp.MustCompile(`^R-[0-9]{3}$`)

func main() {
	release := flag.Bool("release", false, "apply release gate: unresolved high/critical FMEA risks fail")
	flag.Parse()

	root, err := findRepoRoot()
	if err != nil {
		fatalf("%v", err)
	}

	regPath := filepath.Join(root, "risks", "register.json")
	planPath := filepath.Join(root, "MASTER_PLAN.md")

	b, err := os.ReadFile(regPath)
	if err != nil {
		fatalf("read %s: %v", regPath, err)
	}
	var reg register
	if err = json.Unmarshal(b, &reg); err != nil {
		fatalf("parse %s: %v", regPath, err)
	}
	plan, err := os.ReadFile(planPath)
	if err != nil {
		fatalf("read %s: %v", planPath, err)
	}

	errs := validate(reg, string(plan), *release)
	printSummary(reg, *release)
	if len(errs) > 0 {
		fmt.Fprintln(os.Stderr, "\nRisk register validation FAILED:")
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, " -", e)
		}
		os.Exit(1)
	}
	fmt.Println("\nRisk register validation PASS")
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if fileExists(filepath.Join(dir, "risks", "register.json")) && fileExists(filepath.Join(dir, "MASTER_PLAN.md")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("repository root not found from %s", dir)
		}
		dir = parent
	}
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func validate(reg register, plan string, release bool) []string {
	var errs []string
	if reg.SchemaVersion != 1 {
		errs = append(errs, fmt.Sprintf("unsupported schema_version=%d (want 1)", reg.SchemaVersion))
	}
	if strings.TrimSpace(reg.Method) == "" {
		errs = append(errs, "method is empty")
	}
	if reg.ReviewPolicy.HighRPNThreshold <= 0 || reg.ReviewPolicy.CriticalSeverityThreshold < 1 || reg.ReviewPolicy.CriticalSeverityThreshold > 10 {
		errs = append(errs, "review_policy thresholds are invalid")
	}
	if len(reg.Risks) == 0 {
		errs = append(errs, "risk register is empty")
		return errs
	}

	seen := map[string]bool{}
	allowedStatus := map[string]bool{"open": true, "mitigating": true, "accepted": true, "closed": true}

	for i, r := range reg.Risks {
		prefix := fmt.Sprintf("risks[%d]", i)
		if !riskIDRE.MatchString(r.ID) {
			errs = append(errs, fmt.Sprintf("%s invalid id %q", prefix, r.ID))
		}
		if seen[r.ID] {
			errs = append(errs, fmt.Sprintf("duplicate risk id %s", r.ID))
		}
		seen[r.ID] = true

		required := map[string]string{
			"title": r.Title, "component": r.Component, "failure_mode": r.FailureMode,
			"effect": r.Effect, "cause": r.Cause, "owner": r.Owner,
			"target_milestone": r.TargetMilestone, "mitigation": r.Mitigation,
			"verification": r.Verification, "last_reviewed": r.LastReviewed,
		}
		for field, value := range required {
			if strings.TrimSpace(value) == "" {
				errs = append(errs, fmt.Sprintf("%s %s is empty", r.ID, field))
			}
		}
		if !allowedStatus[r.Status] {
			errs = append(errs, fmt.Sprintf("%s invalid status %q", r.ID, r.Status))
		}
		if r.Status == "accepted" && strings.TrimSpace(r.AcceptanceReason) == "" {
			errs = append(errs, fmt.Sprintf("%s accepted risk requires acceptance_reason", r.ID))
		}
		if len(r.Controls) == 0 {
			errs = append(errs, fmt.Sprintf("%s has no current controls", r.ID))
		}
		if len(r.PlanRefs) == 0 && r.Status != "closed" {
			errs = append(errs, fmt.Sprintf("%s has no plan_refs", r.ID))
		}

		for name, score := range map[string]int{"severity": r.Severity, "occurrence": r.Occurrence, "detection": r.Detection} {
			if score < 1 || score > 10 {
				errs = append(errs, fmt.Sprintf("%s %s=%d outside 1..10", r.ID, name, score))
			}
		}
		computed := r.Severity * r.Occurrence * r.Detection
		if r.RPN != computed {
			errs = append(errs, fmt.Sprintf("%s rpn=%d but S*O*D=%d", r.ID, r.RPN, computed))
		}
		if r.InitialRPN <= 0 {
			errs = append(errs, fmt.Sprintf("%s initial_rpn must be positive", r.ID))
		}
		if r.InitialRPN < r.RPN {
			errs = append(errs, fmt.Sprintf("%s initial_rpn=%d is lower than current rpn=%d; explain by resetting baseline instead of implying mitigation", r.ID, r.InitialRPN, r.RPN))
		}
		if _, err := time.Parse("2006-01-02", r.LastReviewed); err != nil {
			errs = append(errs, fmt.Sprintf("%s last_reviewed must be YYYY-MM-DD", r.ID))
		}

		// The planning document is intentionally a second independently checked
		// representation: an unresolved risk that disappears from MASTER_PLAN is
		// treated as a governance failure.
		if r.Status != "closed" && !strings.Contains(plan, r.ID) {
			errs = append(errs, fmt.Sprintf("%s is unresolved but missing from MASTER_PLAN.md", r.ID))
		}

		if release && r.Status != "closed" && r.Status != "accepted" &&
			(r.RPN >= reg.ReviewPolicy.HighRPNThreshold || r.Severity >= reg.ReviewPolicy.CriticalSeverityThreshold) {
			errs = append(errs, fmt.Sprintf("release gate: %s unresolved (S=%d RPN=%d status=%s)", r.ID, r.Severity, r.RPN, r.Status))
		}
	}
	return errs
}

func printSummary(reg register, release bool) {
	risks := append([]risk(nil), reg.Risks...)
	sort.Slice(risks, func(i, j int) bool {
		if risks[i].RPN != risks[j].RPN {
			return risks[i].RPN > risks[j].RPN
		}
		return risks[i].ID < risks[j].ID
	})

	counts := map[string]int{}
	for _, r := range risks {
		counts[r.Status]++
	}
	fmt.Printf("FMEA risks=%d open=%d mitigating=%d accepted=%d closed=%d release_gate=%v\n",
		len(risks), counts["open"], counts["mitigating"], counts["accepted"], counts["closed"], release)
	fmt.Printf("thresholds: RPN>=%d or severity>=%d\n", reg.ReviewPolicy.HighRPNThreshold, reg.ReviewPolicy.CriticalSeverityThreshold)
	fmt.Println("Top current risks:")
	limit := 10
	if len(risks) < limit {
		limit = len(risks)
	}
	for _, r := range risks[:limit] {
		fmt.Printf("  %-5s RPN=%-3d S/O/D=%d/%d/%d %-10s %s\n", r.ID, r.RPN, r.Severity, r.Occurrence, r.Detection, r.Status, r.Title)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "riskcheck: "+format+"\n", args...)
	os.Exit(2)
}
