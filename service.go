package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// relay service keeps a node (or the server) running in the background, at
// login and after reboots, with the platform's own service manager:
//
//	macOS    a launchd agent        ~/Library/LaunchAgents/dev.ghostrelay.<role>[.<name>].plist
//	Linux    a systemd user unit    ~/.config/systemd/user/ghostrelay-<role>[-<name>].service
//	Windows  a Scheduled Task       ghostrelay-<role>[-<name>], at logon, as the current user
//
// All three run as the current user (no admin rights needed) and the same
// command line: relay <role> --config <file> --log-file <file>. The binary is
// first copied to ~/.relay/bin, so deleting the download doesn't break it.

type service struct {
	role, cfg string // "node" or "server"; settings file
	id        string // ghostrelay-node-win
	exe       string // ~/.relay/bin/relay
	logPath   string
}

func newService(role, cfg string) (*service, error) {
	if role != "node" && role != "server" {
		return nil, fmt.Errorf("unknown role %q (node or server)", role)
	}
	if cfg == "" {
		cfg = defaultNodeConfig()
		if role == "server" {
			cfg = defaultServerConfig()
		}
	}
	cfg, _ = filepath.Abs(cfg)
	m, err := readJSONMap(cfg)
	if err != nil {
		hint := "relay join <code>"
		if role == "server" {
			hint = "relay init"
		}
		return nil, fmt.Errorf("%v\n  create the settings first with: %s", err, hint)
	}
	id := "ghostrelay-" + role
	if name, _ := m["name"].(string); role == "node" && name != "" {
		id += "-" + name
	}
	if h := os.Getenv("RELAY_HOME"); h != "" {
		// Another settings folder is another set of services, even when a
		// node there has the same name as one in ~/.relay.
		abs, _ := filepath.Abs(h)
		sum := sha256.Sum256([]byte(abs))
		id += "-" + hex.EncodeToString(sum[:3])
	}
	return &service{role: role, cfg: cfg, id: id, exe: serviceExe(),
		logPath: filepath.Join(relayHome(), "logs", id+".log")}, nil
}

// serviceExe is the copy of relay that services run: ~/.relay/bin/relay.
func serviceExe() string {
	exe := "relay"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	return filepath.Join(relayHome(), "bin", exe)
}

func (s *service) args() []string {
	return []string{s.role, "--config", s.cfg, "--log-file", s.logPath}
}

func runService(args []string) {
	fs := flag.NewFlagSet("service", flag.ExitOnError)
	cfg := fs.String("config", "", "settings file (default: ~/.relay/node.json, or ~/.relay/server/server.json for server)")
	lines := fs.Int("n", 40, "logs: how many lines to show")
	follow := fs.Bool("f", false, "logs: keep printing new lines")
	pos := parseInterleaved(fs, args)
	if len(pos) < 1 || len(pos) > 2 {
		log.Fatal("usage: relay service <install|uninstall|status|logs> [node|server] [--config FILE]")
	}
	role := "node"
	if len(pos) == 2 {
		role = pos[1]
	}
	var err error
	switch pos[0] {
	case "install":
		err = serviceInstall(role, *cfg)
	case "uninstall", "remove":
		var s *service
		if s, err = newService(role, *cfg); err == nil {
			err = s.uninstall()
		}
	case "status":
		var s *service
		if s, err = newService(role, *cfg); err == nil {
			fmt.Printf("%s: %s\n", s.id, s.status())
		}
	case "logs":
		var s *service
		if s, err = newService(role, *cfg); err == nil {
			err = tailFile(s.logPath, *lines, *follow)
		}
	default:
		err = fmt.Errorf("unknown action %q (install, uninstall, status, logs)", pos[0])
	}
	if err != nil {
		log.Fatal(err)
	}
}

func serviceInstall(role, cfg string) error {
	s, err := newService(role, cfg)
	if err != nil {
		return err
	}
	s.stop() // an older install may hold the binary open (Windows)
	if err := s.copyBinary(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.logPath), 0o700); err != nil {
		return err
	}
	switch runtime.GOOS {
	case "darwin":
		err = s.installLaunchd()
	case "linux":
		err = s.installSystemd()
	case "windows":
		err = s.installTask()
	default:
		err = fmt.Errorf("relay service doesn't support %s yet; run `relay %s --config %s` from your init system", runtime.GOOS, role, s.cfg)
	}
	if err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	fmt.Printf("installed %s: %s\n  settings %s\n  log      %s   (relay service logs)\n", s.id, s.status(), s.cfg, s.logPath)
	if tail, _ := lastLines(s.logPath, 3); tail != "" {
		fmt.Println("  last log lines:\n    " + strings.ReplaceAll(strings.TrimSpace(tail), "\n", "\n    "))
	}
	return nil
}

// copyBinary puts this executable at ~/.relay/bin, unless it already runs from there.
func (s *service) copyBinary() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.EvalSymlinks(self)
	if want, _ := filepath.EvalSymlinks(s.exe); want == self {
		return nil
	}
	src, err := os.Open(self)
	if err != nil {
		return err
	}
	defer src.Close()
	if err := os.MkdirAll(filepath.Dir(s.exe), 0o755); err != nil {
		return err
	}
	tmp := s.exe + ".new"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	dst.Close()
	if err := os.Rename(tmp, s.exe); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace %s: %v (is an old copy still running? relay service uninstall)", s.exe, err)
	}
	return nil
}

func (s *service) stop() {
	switch runtime.GOOS {
	case "darwin":
		run("launchctl", "bootout", s.launchdTarget())
	case "linux":
		run("systemctl", "--user", "stop", s.id)
	case "windows":
		powershell(fmt.Sprintf("Stop-ScheduledTask -TaskName %s -ErrorAction SilentlyContinue", psQuote(s.id)))
	}
}

// start (re)registers the service and starts it, with its current files.
func (s *service) start() error {
	switch runtime.GOOS {
	case "darwin":
		return s.installLaunchd()
	case "linux":
		return s.installSystemd()
	case "windows":
		return s.installTask()
	}
	return fmt.Errorf("relay service doesn't support %s", runtime.GOOS)
}

func (s *service) uninstall() error {
	s.stop()
	var err error
	switch runtime.GOOS {
	case "darwin":
		err = os.Remove(s.plistPath())
	case "linux":
		run("systemctl", "--user", "disable", s.id)
		err = os.Remove(s.unitPath())
		run("systemctl", "--user", "daemon-reload")
	case "windows":
		_, err = powershell(fmt.Sprintf("Unregister-ScheduledTask -TaskName %s -Confirm:$false -ErrorAction Stop", psQuote(s.id)))
	default:
		err = fmt.Errorf("relay service doesn't support %s", runtime.GOOS)
	}
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s is not installed", s.id)
	}
	if err == nil {
		fmt.Printf("removed %s (settings and logs are kept in %s)\n", s.id, relayHome())
	}
	return err
}

// installed reports whether the service is set up, whatever its state.
func (s *service) installed() bool {
	switch runtime.GOOS {
	case "darwin":
		_, err := os.Stat(s.plistPath())
		return err == nil
	case "linux":
		_, err := os.Stat(s.unitPath())
		return err == nil
	}
	return s.status() != "not installed"
}

func (s *service) status() string {
	switch runtime.GOOS {
	case "darwin":
		out, err := run("launchctl", "print", s.launchdTarget())
		if err != nil {
			return "not installed"
		}
		state, pid := field(out, "state = "), field(out, "pid = ")
		if pid != "" {
			return state + ", pid " + pid
		}
		return state
	case "linux":
		out, _ := run("systemctl", "--user", "is-active", s.id)
		st := strings.TrimSpace(out)
		if pid, _ := run("systemctl", "--user", "show", "-p", "MainPID", "--value", s.id); st == "active" && strings.TrimSpace(pid) != "0" {
			st += ", pid " + strings.TrimSpace(pid)
		}
		return st
	case "windows":
		out, err := powershell(fmt.Sprintf("$t = Get-ScheduledTask -TaskName %s -ErrorAction Stop; $i = $t | Get-ScheduledTaskInfo; \"$($t.State) $($i.LastTaskResult)\"", psQuote(s.id)))
		if err != nil {
			return "not installed"
		}
		return taskState(strings.TrimSpace(out))
	}
	return "unknown"
}

// ---- macOS: launchd --------------------------------------------------------------

func (s *service) label() string {
	return "dev." + strings.Replace(s.id, "-", ".", 2) // dev.ghostrelay.node.win
}
func (s *service) launchdTarget() string { return fmt.Sprintf("gui/%d/%s", os.Getuid(), s.label()) }
func (s *service) plistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", s.label()+".plist")
}

func (s *service) installLaunchd() error {
	if err := os.MkdirAll(filepath.Dir(s.plistPath()), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(s.plistPath(), []byte(s.launchdPlist()), 0o644); err != nil {
		return err
	}
	if out, err := run("launchctl", "bootstrap", fmt.Sprintf("gui/%d", os.Getuid()), s.plistPath()); err != nil {
		return fmt.Errorf("launchctl bootstrap: %v %s", err, out)
	}
	return nil
}

func (s *service) launchdPlist() string {
	esc := func(v string) string { var b bytes.Buffer; xml.EscapeText(&b, []byte(v)); return b.String() }
	var argv strings.Builder
	for _, a := range append([]string{s.exe}, s.args()...) {
		argv.WriteString("\n    <string>" + esc(a) + "</string>")
	}
	// launchd starts agents with a bare PATH; keep the user's, so probed tools
	// (git, ffmpeg in /opt/homebrew/bin...) are found as in a terminal.
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>%s
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>%s</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, esc(s.label()), argv.String(), esc(os.Getenv("PATH")), esc(s.logPath))
}

// ---- Linux: systemd user unit ----------------------------------------------------

func (s *service) unitPath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "systemd", "user", s.id+".service")
}

func (s *service) installSystemd() error {
	if err := os.MkdirAll(filepath.Dir(s.unitPath()), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(s.unitPath(), []byte(s.systemdUnit()), 0o644); err != nil {
		return err
	}
	if out, err := run("systemctl", "--user", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl --user: %v %s\n  this needs a systemd user session (log in normally, not just `su`)", err, out)
	}
	if out, err := run("systemctl", "--user", "enable", "--now", s.id); err != nil {
		return fmt.Errorf("systemctl --user enable: %v %s", err, out)
	}
	if out, _ := run("loginctl", "show-user", os.Getenv("USER"), "-p", "Linger", "--value"); strings.TrimSpace(out) != "yes" {
		fmt.Println("note: it starts when you log in. To start it at boot without logging in, run once:\n  sudo loginctl enable-linger " + os.Getenv("USER"))
	}
	return nil
}

func (s *service) systemdUnit() string {
	q := func(v string) string { // systemd quoting; % starts a specifier
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace(v) + `"`
	}
	var cmd []string
	for _, a := range append([]string{s.exe}, s.args()...) {
		cmd = append(cmd, q(a))
	}
	return fmt.Sprintf(`[Unit]
Description=ghostrelay %s (%s)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s
Restart=always
RestartSec=5
Environment=%s

[Install]
WantedBy=default.target
`, s.role, s.id, strings.Join(cmd, " "), q("PATH="+os.Getenv("PATH")))
}

// ---- Windows: Scheduled Task -----------------------------------------------------

// A logon task as the current user needs no admin rights, sees the user's
// PATH and files, and restarts on failure. The process hides the console
// window Task Scheduler opens for it (see hideOwnConsole).
func (s *service) installTask() error {
	if out, err := powershell(s.taskScript()); err != nil {
		return fmt.Errorf("register scheduled task: %v\n%s", err, out)
	}
	return nil
}

func (s *service) taskScript() string {
	var argv []string
	for _, a := range s.args() {
		argv = append(argv, `"`+a+`"`)
	}
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$a = New-ScheduledTaskAction -Execute %s -Argument %s
$t = New-ScheduledTaskTrigger -AtLogOn -User $user
$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
$p = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName %s -Action $a -Trigger $t -Settings $s -Principal $p -Description 'ghostrelay %s' -Force | Out-Null
Start-ScheduledTask -TaskName %s`, psQuote(s.exe), psQuote(strings.Join(argv, " ")), psQuote(s.id), s.role, psQuote(s.id))
}

// taskState turns "Running 267009" (state, LastTaskResult) into words.
// Task Scheduler reports its own SCHED_S_* codes as the last result.
func taskState(out string) string {
	state, code, _ := strings.Cut(out, " ")
	switch code {
	case "0", "":
		return strings.ToLower(state)
	case "267009": // 0x41301 SCHED_S_TASK_RUNNING
		return strings.ToLower(state)
	case "267011": // 0x41303 SCHED_S_TASK_HAS_NOT_RUN
		return strings.ToLower(state) + " (has not run yet)"
	case "267014": // 0x41306 SCHED_S_TASK_TERMINATED
		return strings.ToLower(state) + " (last run was stopped)"
	}
	return fmt.Sprintf("%s (last exit code %s; see relay service logs)", strings.ToLower(state), code)
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func powershell(script string) (string, error) {
	return run("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
}

// ---- helpers ---------------------------------------------------------------------

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func field(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), key); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func lastLines(path string, n int) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func tailFile(path string, n int, follow bool) error {
	out, err := lastLines(path, n)
	if err != nil {
		return fmt.Errorf("%v (is the service installed? relay service status)", err)
	}
	fmt.Print(out)
	if !follow {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	off, _ := f.Seek(0, io.SeekEnd)
	buf := make([]byte, 64<<10)
	for {
		time.Sleep(500 * time.Millisecond)
		if st, err := os.Stat(path); err == nil && st.Size() < off {
			f.Close() // rotated
			if f, err = os.Open(path); err != nil {
				return err
			}
			off = 0
		}
		for {
			n, _ := f.ReadAt(buf, off)
			if n == 0 {
				break
			}
			os.Stdout.Write(buf[:n])
			off += int64(n)
		}
	}
}
