package platform

import (
	"fmt"
	"os/exec"
	"runtime"
)

func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows": cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "linux": cmd = exec.Command("xdg-open", url)
	default: return fmt.Errorf("unsupported OS for browser launch: %s", runtime.GOOS)
	}
	return cmd.Start()
}
