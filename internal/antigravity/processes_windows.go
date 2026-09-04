//go:build windows

package antigravity

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

type windowsProcess struct {
	ProcessID       int     `json:"ProcessId"`
	ParentProcessID int     `json:"ParentProcessId"`
	Name            string  `json:"Name"`
	ExecutablePath  *string `json:"ExecutablePath"`
	CommandLine     *string `json:"CommandLine"`
}

func listPlatformProcesses() ([]ProcessInfo, error) {
	shell := "powershell.exe"
	if _, err := exec.LookPath(shell); err != nil {
		if _, pwshErr := exec.LookPath("pwsh.exe"); pwshErr != nil {
			return nil, fmt.Errorf("neither powershell.exe nor pwsh.exe is available")
		}
		shell = "pwsh.exe"
	}
	script := `$p = Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine; ConvertTo-Json -Compress -Depth 3 -InputObject @($p)`
	out, err := exec.Command(shell, "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("Win32_Process inventory: %w: %s", err, string(out))
	}
	var raw []windowsProcess
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("decode Win32_Process inventory: %w", err)
	}
	result := make([]ProcessInfo, 0, len(raw))
	for _, p := range raw {
		item := ProcessInfo{PID: p.ProcessID, PPID: p.ParentProcessID, Name: p.Name}
		if p.ExecutablePath != nil {
			item.Executable = *p.ExecutablePath
		}
		if p.CommandLine != nil {
			item.CommandLine = *p.CommandLine
		}
		result = append(result, item)
	}
	return result, nil
}
