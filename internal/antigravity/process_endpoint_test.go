package antigravity

import "testing"

func TestProcessTreeSurfacesLearnedBackendEndpoints(t *testing.T) {
	report := buildAgentProcessTree([]ProcessInfo{
		{PID: 10, Name: "antigravity", CommandLine: "antigravity --backend https://new-backend.example.test"},
		{PID: 11, PPID: 10, Name: "language_server", CommandLine: "language_server --endpoint https://agent.new-google.test:443"},
	})
	if len(report.LearnedEndpoints) != 2 {
		t.Fatalf("learned endpoints=%v want two reviewed candidates", report.LearnedEndpoints)
	}
	if report.LearnedEndpoints[0] != "agent.new-google.test" || report.LearnedEndpoints[1] != "new-backend.example.test" {
		t.Fatalf("unexpected learned endpoints=%v", report.LearnedEndpoints)
	}
}
