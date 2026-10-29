//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// setProcGroup puts the command in its own process group so killTree can
// take down everything it spawned.
func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killTree(cmd *exec.Cmd) {
	if cmd.Process != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

func isCrossDevice(err error) bool { return err == syscall.EXDEV }

func hideOwnConsole() {}
