package antigravity

import (
	"regexp"
	"sort"
	"strings"
)

type ProcessInfo struct {
	PID         int    `json:"pid"`
	PPID        int    `json:"ppid"`
	Name        string `json:"name"`
	Executable  string `json:"executable,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	Role        string `json:"role"`
	Known       bool   `json:"known"`
}

type ProcessTreeReport struct {
	Processes        []ProcessInfo `json:"processes"`
	UnknownHelpers   []ProcessInfo `json:"unknown_helpers,omitempty"`
	RootPIDs         []int         `json:"root_pids,omitempty"`
	Complete         bool          `json:"complete"`
	Detail           string        `json:"detail,omitempty"`
	LearnedEndpoints []string      `json:"learned_endpoints,omitempty"`
}

var endpointCandidateRE = regexp.MustCompile(`(?i)\b(?:https?://)?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?::[0-9]{1,5})?\b`)

// DiscoverAgentProcessTree inventories the live Antigravity process tree. It
// deliberately includes unknown descendants: a new helper must become visible
// as degraded evidence instead of silently escaping a static name allowlist.
func DiscoverAgentProcessTree() ProcessTreeReport {
	all, err := listPlatformProcesses()
	if err != nil {
		return ProcessTreeReport{Complete: false, Detail: err.Error()}
	}
	return buildAgentProcessTree(all)
}

func buildAgentProcessTree(all []ProcessInfo) ProcessTreeReport {
	byParent := make(map[int][]ProcessInfo)
	roots := make([]ProcessInfo, 0)
	for _, p := range all {
		byParent[p.PPID] = append(byParent[p.PPID], p)
		if isAntigravityRoot(p) {
			roots = append(roots, p)
		}
	}

	selected := make(map[int]ProcessInfo)
	queue := append([]ProcessInfo(nil), roots...)
	rootPIDs := make([]int, 0, len(roots))
	for _, r := range roots {
		rootPIDs = append(rootPIDs, r.PID)
	}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if _, seen := selected[p.PID]; seen {
			continue
		}
		p.Role, p.Known = classifyAgentProcess(p)
		selected[p.PID] = p
		queue = append(queue, byParent[p.PID]...)
	}

	processes := make([]ProcessInfo, 0, len(selected))
	unknown := make([]ProcessInfo, 0)
	learned := make([]string, 0)
	for _, p := range selected {
		processes = append(processes, p)
		if !p.Known {
			unknown = append(unknown, p)
		}
		for _, match := range endpointCandidateRE.FindAllStringSubmatch(p.CommandLine, -1) {
			if len(match) > 1 && !isCommonNonBackendHost(match[1]) && !containsString(learned, strings.ToLower(match[1])) {
				learned = append(learned, strings.ToLower(match[1]))
			}
		}
	}
	sort.Slice(processes, func(i, j int) bool { return processes[i].PID < processes[j].PID })
	sort.Slice(unknown, func(i, j int) bool { return unknown[i].PID < unknown[j].PID })
	sort.Ints(rootPIDs)
	sort.Strings(learned)

	detail := "no running Antigravity process tree found"
	if len(processes) > 0 {
		detail = "live Antigravity process tree inventoried"
	}
	return ProcessTreeReport{
		Processes:        processes,
		UnknownHelpers:   unknown,
		RootPIDs:         rootPIDs,
		Complete:         true,
		Detail:           detail,
		LearnedEndpoints: learned,
	}
}

func isCommonNonBackendHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "example.com", "example.org", "example.net":
		return true
	default:
		return false
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func isAntigravityRoot(p ProcessInfo) bool {
	name := strings.ToLower(strings.TrimSpace(p.Name))
	exe := strings.ToLower(p.Executable)
	cmd := strings.ToLower(p.CommandLine)
	if strings.Contains(name, "antigravity") || strings.Contains(exe, "antigravity") {
		return true
	}
	// Some launchers expose a generic executable name but retain the product
	// path/argument in the command line.
	return strings.Contains(cmd, "antigravity") && !strings.Contains(name, "antigraviti-proxi")
}

func classifyAgentProcess(p ProcessInfo) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(p.Name))
	exe := strings.ToLower(p.Executable)
	cmd := strings.ToLower(p.CommandLine)
	joined := name + " " + exe + " " + cmd

	switch {
	case strings.Contains(name, "antigravity"):
		return "ide", true
	case strings.Contains(name, "language_server") || strings.Contains(name, "language-server"):
		return "language-server", true
	case name == "agy" || name == "agy.exe":
		return "agent-helper", true
	case (name == "node" || name == "node.exe") && strings.Contains(joined, "antigravity"):
		return "bundled-node", true
	case strings.Contains(exe, "antigravity") || strings.Contains(cmd, "antigravity"):
		return "product-helper", true
	default:
		return "unknown-descendant", false
	}
}
