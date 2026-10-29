//go:build windows

package main

import (
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
}

// killTree uses taskkill /T, which follows the parent/child chain that a
// plain Process.Kill would leave running.
func killTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
	cmd.Process.Kill()
}

// ERROR_NOT_SAME_DEVICE: MoveFileEx cannot rename across volumes.
func isCrossDevice(err error) bool { return err == syscall.Errno(17) }

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleProcess = kernel32.NewProc("GetConsoleProcessList")
	procFreeConsole       = kernel32.NewProc("FreeConsole")
)

// hideOwnConsole closes the console window when this process is the only one
// using it, which is the case when Task Scheduler started it. Started from a
// terminal, the shell shares the console, and it is left alone.
func hideOwnConsole() {
	var pids [2]uint32
	n, _, _ := procGetConsoleProcess.Call(uintptr(unsafe.Pointer(&pids[0])), 2)
	if n == 1 {
		procFreeConsole.Call()
	}
}
