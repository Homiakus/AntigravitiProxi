package antigravity

import "testing"

func TestBuildAgentProcessTreeIncludesUnknownDescendants(t *testing.T) {
	all := []ProcessInfo{
		{PID: 100, PPID: 1, Name: "antigravity", Executable: "/opt/antigravity/antigravity"},
		{PID: 101, PPID: 100, Name: "language_server"},
		{PID: 102, PPID: 100, Name: "node", Executable: "/opt/antigravity/resources/node"},
		{PID: 103, PPID: 102, Name: "new-helper-v7", Executable: "/tmp/helper"},
		{PID: 200, PPID: 1, Name: "node", Executable: "/usr/bin/node"},
	}
	r := buildAgentProcessTree(all)
	if !r.Complete {
		t.Fatal("synthetic inventory should be complete")
	}
	if len(r.Processes) != 4 {
		t.Fatalf("processes=%d want 4", len(r.Processes))
	}
	if len(r.UnknownHelpers) != 1 || r.UnknownHelpers[0].PID != 103 {
		t.Fatalf("unknown helpers=%#v", r.UnknownHelpers)
	}
}

func TestBuildAgentProcessTreeDoesNotCaptureUnrelatedNode(t *testing.T) {
	r := buildAgentProcessTree([]ProcessInfo{
		{PID: 10, PPID: 1, Name: "node", Executable: "/usr/bin/node", CommandLine: "node server.js"},
	})
	if len(r.Processes) != 0 {
		t.Fatalf("unrelated process captured: %#v", r.Processes)
	}
}
