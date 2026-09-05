package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/antigravity"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent-doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	strictExit := fs.Bool("strict-exit", false, "return exit code 2 when the diagnostic result is inconclusive")
	timeout := fs.Duration("timeout", 45*time.Second, "maximum log-scan duration")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "timeout must be greater than zero")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	report := antigravity.AgentDoctor(ctx)
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	if ctx.Err() != nil && report.FilesScanned == 0 {
		fmt.Fprintln(stderr, "Agent Doctor timed out before any log file was scanned")
		return 1
	}
	return exitCodeForReport(report, *strictExit)
}

func exitCodeForReport(report antigravity.AgentDoctorReport, strict bool) int {
	// "unknown" means the scan completed but did not contain a sufficiently
	// specific known signature. That is an inconclusive diagnostic result, not
	// a CLI execution failure. Keep non-zero behavior available for scripts that
	// deliberately want to gate on diagnostic certainty.
	if strict && report.LikelyCause == "unknown" {
		return 2
	}
	return 0
}
