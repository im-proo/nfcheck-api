package cookiefetch

import (
	"os/exec"
)

// safeExec runs an external binary safely with argument vector (no shell injection).
func safeExec(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}
