package audit

import (
	"fmt"
	"path"
	"strings"
	"time"
)

// Schedule is how to seal and rotate a decision log on a timer, on one platform.
//
// It exists because a seal nobody schedules is a seal taken once. The first real
// installation was sealed by hand at line 7,622 and then not again, and a log sealed
// once reads exactly like a log under tamper-evidence: the chain file is there, verify
// passes, and every line written since is covered by nothing. The gap between seals is
// the window an edit can hide in, so the interval is the control.
//
// Reeve writes no scheduler entry itself. Installing a timer is a standing change to
// somebody's machine that outlives the command that made it, and the person whose
// machine it is should see exactly what is being installed and run it themselves. So
// this is a plan - the files and the commands - printed rather than executed.
type Schedule struct {
	Platform string         `json:"platform"`
	Files    []ScheduleFile `json:"files,omitempty"`
	// Install and Remove are commands to run in order. Remove undoes Install.
	Install []string `json:"install"`
	Remove  []string `json:"remove"`
	// Notes are what an operator needs to know that the commands cannot say.
	Notes []string `json:"notes,omitempty"`
}

// ScheduleFile is a file the plan asks to be written before Install runs.
type ScheduleFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// ScheduleOptions describes what to schedule.
type ScheduleOptions struct {
	// Platform is windows, linux or darwin.
	Platform string
	// Home is the home directory of the account the timers run as, on that platform.
	Home string
	// Binary and Log are absolute paths on the target platform.
	Binary string
	Log    string
	// Every is how often to seal. Whole minutes, at least one.
	Every time.Duration
	// Keep is passed to rotate as --keep. Zero rotates without removing anything,
	// which is what the free edition promises by default: kept for as long as
	// configured, and no less.
	Keep time.Duration
}

// The names the timers are installed under. Fixed, so the remove commands can find
// them again and a second run replaces rather than duplicates.
const (
	taskSeal   = "Reeve - seal decision log"
	taskRotate = "Reeve - rotate decision log"
	unitSeal   = "reeve-seal"
	unitRotate = "reeve-rotate"
	labelSeal  = "local.reeve.seal"
	labelRot   = "local.reeve.rotate"
)

// PlanSchedule returns the plan for one platform.
//
// Every path is checked as an absolute path on the target platform, not this one: a
// timer runs with no working directory anybody chose, and a relative path there seals
// a file that is not the log, or fails every hour into a log nobody reads.
func PlanSchedule(o ScheduleOptions) (Schedule, error) {
	switch {
	case o.Every < time.Minute:
		return Schedule{}, fmt.Errorf("--every %s is shorter than a minute", o.Every)
	case o.Every%time.Minute != 0:
		return Schedule{}, fmt.Errorf("--every %s is not a whole number of minutes, which no scheduler here can express", o.Every)
	case o.Keep < 0:
		return Schedule{}, fmt.Errorf("--keep %s is negative", o.Keep)
	}
	for _, p := range []struct{ name, value string }{{"binary", o.Binary}, {"log", o.Log}} {
		if !absoluteOn(o.Platform, p.value) {
			return Schedule{}, fmt.Errorf("the %s path %q is not absolute on %s; a timer runs with no working directory to resolve it against",
				p.name, p.value, o.Platform)
		}
	}
	rotate := []string{o.Binary, "audit", "rotate", o.Log}
	if o.Keep > 0 {
		rotate = append(rotate, "--keep", ShortDuration(o.Keep))
	}
	seal := []string{o.Binary, "audit", "seal", o.Log}

	switch o.Platform {
	case "windows":
		return windowsSchedule(o, seal, rotate), nil
	case "linux":
		if !absoluteOn("linux", o.Home) {
			return Schedule{}, fmt.Errorf("the home directory %q is not absolute", o.Home)
		}
		return linuxSchedule(o, seal, rotate), nil
	case "darwin":
		if !absoluteOn("darwin", o.Home) {
			return Schedule{}, fmt.Errorf("the home directory %q is not absolute", o.Home)
		}
		return darwinSchedule(o, seal, rotate), nil
	}
	return Schedule{}, fmt.Errorf("no schedule for platform %q: expected windows, linux or darwin", o.Platform)
}

// windowsSchedule registers two Task Scheduler tasks from PowerShell.
//
// Through conhost --headless, because a console program run by the scheduler opens a
// window, and a window flashing up every hour is what gets a task deleted by the person
// whose screen it is. Output goes to seal.log beside the log, because a scheduled task's
// output otherwise goes nowhere, and a seal that has been failing for a month looks,
// from the chain file, like a seal that stopped being needed.
func windowsSchedule(o ScheduleOptions, seal, rotate []string) Schedule {
	out := windowsDir(o.Log) + `\seal.log`
	action := func(argv []string) string {
		cmd := `--headless cmd.exe /d /c "` + cmdLine(argv) + ` >> ` + cmdQuote(out) + ` 2>&1"`
		return `New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\conhost.exe" -Argument ` + psQuote(cmd)
	}
	minutes := int(o.Every / time.Minute)
	return Schedule{
		Platform: "windows",
		Install: []string{
			`$seal = ` + action(seal),
			`Register-ScheduledTask -Force -TaskName ` + psQuote(taskSeal) + ` -Action $seal ` +
				fmt.Sprintf(`-Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes %d)) `, minutes) +
				`-Description 'Seals the Reeve decision log, so a later edit to it can be detected.'`,
			`$rotate = ` + action(rotate),
			`Register-ScheduledTask -Force -TaskName ` + psQuote(taskRotate) + ` -Action $rotate ` +
				`-Trigger (New-ScheduledTaskTrigger -Daily -At 03:10) ` +
				`-Description 'Rotates the Reeve decision log into sealed segments.'`,
		},
		Remove: []string{
			`Unregister-ScheduledTask -TaskName ` + psQuote(taskSeal) + ` -Confirm:$false`,
			`Unregister-ScheduledTask -TaskName ` + psQuote(taskRotate) + ` -Confirm:$false`,
		},
		Notes: []string{
			"Run these in PowerShell as the account whose agents the guard decides for. They need no administrator rights.",
			"Output and errors go to " + out + ". Read it if verify ever reports the log unsealed.",
		},
	}
}

// linuxSchedule is a pair of systemd user timers.
//
// Persistent, so a machine that was off at the hour seals when it next starts rather
// than leaving the gap open until the next interval. User timers stop at logout unless
// lingering is enabled, which is said in a note rather than done: it changes what runs
// on the machine when nobody is logged in.
func linuxSchedule(o ScheduleOptions, seal, rotate []string) Schedule {
	dir := path.Join(o.Home, ".config", "systemd", "user")
	unit := func(desc string, argv []string) string {
		return "[Unit]\nDescription=" + desc + "\n\n[Service]\nType=oneshot\nExecStart=" + systemdLine(argv) + "\n"
	}
	return Schedule{
		Platform: "linux",
		Files: []ScheduleFile{
			{path.Join(dir, unitSeal+".service"), unit("Seal the Reeve decision log", seal)},
			{path.Join(dir, unitSeal+".timer"), fmt.Sprintf(
				"[Unit]\nDescription=Seal the Reeve decision log every %s\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=%dmin\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
				ShortDuration(o.Every), int(o.Every/time.Minute))},
			{path.Join(dir, unitRotate+".service"), unit("Rotate the Reeve decision log into sealed segments", rotate)},
			{path.Join(dir, unitRotate+".timer"),
				"[Unit]\nDescription=Rotate the Reeve decision log daily\n\n[Timer]\nOnCalendar=*-*-* 03:10:00\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"},
		},
		Install: []string{
			"systemctl --user daemon-reload",
			"systemctl --user enable --now " + unitSeal + ".timer " + unitRotate + ".timer",
		},
		Remove: []string{
			"systemctl --user disable --now " + unitSeal + ".timer " + unitRotate + ".timer",
			"rm " + shQuote(path.Join(dir, unitSeal+".service")) + " " + shQuote(path.Join(dir, unitSeal+".timer")) + " " +
				shQuote(path.Join(dir, unitRotate+".service")) + " " + shQuote(path.Join(dir, unitRotate+".timer")),
			"systemctl --user daemon-reload",
		},
		Notes: []string{
			"User timers run only while the account is logged in. On a machine agents use unattended, run: loginctl enable-linger",
			"Output and errors go to the journal: journalctl --user -u " + unitSeal,
		},
	}
}

// darwinSchedule is a pair of launchd agents.
func darwinSchedule(o ScheduleOptions, seal, rotate []string) Schedule {
	dir := path.Join(o.Home, "Library", "LaunchAgents")
	out := path.Join(path.Dir(o.Log), "seal.log")
	plist := func(label string, argv []string, when string) string {
		var args strings.Builder
		for _, a := range argv {
			args.WriteString("    <string>" + xmlEscape(a) + "</string>\n")
		}
		return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>` + label + `</string>
  <key>ProgramArguments</key>
  <array>
` + args.String() + `  </array>
` + when + `  <key>StandardOutPath</key>
  <string>` + xmlEscape(out) + `</string>
  <key>StandardErrorPath</key>
  <string>` + xmlEscape(out) + `</string>
</dict>
</plist>
`
	}
	sealPath := path.Join(dir, labelSeal+".plist")
	rotPath := path.Join(dir, labelRot+".plist")
	return Schedule{
		Platform: "darwin",
		Files: []ScheduleFile{
			{sealPath, plist(labelSeal, seal, fmt.Sprintf("  <key>StartInterval</key>\n  <integer>%d</integer>\n", int(o.Every/time.Second)))},
			{rotPath, plist(labelRot, rotate,
				"  <key>StartCalendarInterval</key>\n  <dict>\n    <key>Hour</key>\n    <integer>3</integer>\n    <key>Minute</key>\n    <integer>10</integer>\n  </dict>\n")},
		},
		Install: []string{
			`launchctl bootstrap gui/$(id -u) ` + shQuote(sealPath),
			`launchctl bootstrap gui/$(id -u) ` + shQuote(rotPath),
		},
		Remove: []string{
			`launchctl bootout gui/$(id -u) ` + shQuote(sealPath),
			`launchctl bootout gui/$(id -u) ` + shQuote(rotPath),
			"rm " + shQuote(sealPath) + " " + shQuote(rotPath),
		},
		Notes: []string{"Output and errors go to " + out + "."},
	}
}

// absoluteOn reports whether p is absolute on the given platform, which need not be
// the one this runs on: a plan for a Windows machine can be printed on a Linux one.
func absoluteOn(platform, p string) bool {
	if platform == "windows" {
		return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') ||
			strings.HasPrefix(p, `\\`)
	}
	return strings.HasPrefix(p, "/")
}

// windowsDir is the directory part of a Windows path, whichever separator it uses.
func windowsDir(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i > 0 {
		return p[:i]
	}
	return p
}

// cmdQuote quotes one argument for cmd.exe. A Windows path cannot contain a double
// quote, so wrapping it is enough.
func cmdQuote(s string) string { return `"` + s + `"` }

func cmdLine(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = cmdQuote(a)
	}
	return strings.Join(q, " ")
}

// psQuote is a PowerShell single-quoted string, in which only ' is special.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// shQuote is a POSIX shell single-quoted string.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// systemdLine quotes a command line for ExecStart. systemd splits on whitespace,
// honours double quotes and backslash escapes, and expands % specifiers, so a path with
// a space or a percent sign would otherwise run something else.
func systemdLine(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		a = strings.ReplaceAll(a, `\`, `\\`)
		a = strings.ReplaceAll(a, `"`, `\"`)
		a = strings.ReplaceAll(a, "%", "%%")
		q[i] = `"` + a + `"`
	}
	return strings.Join(q, " ")
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

// ShortDuration prints 720h rather than 720h0m0s. Both parse; one is what a person
// would have typed.
func ShortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}
