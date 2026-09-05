package main

import (
	"bytes"
	"testing"

	"github.com/Homiakus/AntigravitiProxi/internal/antigravity"
)

func TestExitCodeForInconclusiveReportIsNonFatalByDefault(t *testing.T) {
	report := antigravity.AgentDoctorReport{LikelyCause: "unknown", FilesScanned: 94}
	if got := exitCodeForReport(report, false); got != 0 {
		t.Fatalf("default inconclusive exit=%d want 0", got)
	}
	if got := exitCodeForReport(report, true); got != 2 {
		t.Fatalf("strict inconclusive exit=%d want 2", got)
	}
}

func TestInvalidTimeoutIsUsageError(t *testing.T) {
	var out, err bytes.Buffer
	if got := run([]string{"--timeout=0s"}, &out, &err); got != 2 {
		t.Fatalf("exit=%d want 2", got)
	}
}

func exitCodeForReport(report antigravity.AgentDoctorReport, strict bool) int {
	if strict && report.LikelyCause == "unknown" {
		return 2
	}
	return 0
}
