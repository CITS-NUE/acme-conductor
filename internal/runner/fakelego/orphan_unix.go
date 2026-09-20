//go:build unix

package fakelego

import (
	"os"
	"os/exec"
	"syscall"
)

// spawnOrphan starts this same binary in "sleep" mode in a new session so
// it is not in the caller's process group, with stdout inherited.
func spawnOrphan() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "--path", "/nonexistent", "--domains", "x", "--server", "https://x", "--email", "x", "--dns", "x", "run")
	cmd.Env = append(os.Environ(), EnvMode+"=sleep", EnvRecord+"=")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}
