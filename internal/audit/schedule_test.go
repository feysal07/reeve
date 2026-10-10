package audit

import (
	"strings"
	"testing"
	"time"
)

func plan(t *testing.T, o ScheduleOptions) Schedule {
	t.Helper()
	if o.Every == 0 {
		o.Every = time.Hour
	}
	s, err := PlanSchedule(o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func allText(s Schedule) string {
	var b strings.Builder
	for _, f := range s.Files {
		b.WriteString(f.Path + "\n" + f.Content + "\n")
	}
	b.WriteString(strings.Join(s.Install, "\n") + "\n" + strings.Join(s.Remove, "\n"))
	return b.String()
}

// TestEveryPlatformSealsAndRotatesAndCanBeRemoved. A plan without a way back is a
// standing change nobody can undo from what they were shown.
func TestEveryPlatformSealsAndRotatesAndCanBeRemoved(t *testing.T) {
	for _, o := range []ScheduleOptions{
		{Platform: "windows", Binary: `C:\Tools\reeve.exe`, Log: `C:\Users\dev\.reeve\decisions.jsonl`},
		{Platform: "linux", Home: "/home/dev", Binary: "/opt/reeve", Log: "/home/dev/.reeve/decisions.jsonl"},
		{Platform: "darwin", Home: "/Users/dev", Binary: "/opt/reeve", Log: "/Users/dev/.reeve/decisions.jsonl"},
	} {
		t.Run(o.Platform, func(t *testing.T) {
			s := plan(t, o)
			text := allText(s)
			for _, want := range []string{"audit", "seal", "rotate", "decisions.jsonl"} {
				if !strings.Contains(text, want) {
					t.Errorf("plan does not mention %q:\n%s", want, text)
				}
			}
			if len(s.Install) == 0 || len(s.Remove) == 0 {
				t.Errorf("install %d, remove %d commands", len(s.Install), len(s.Remove))
			}
		})
	}
}

// TestTheIntervalReachesTheScheduler. The interval is the control: an hourly seal
// printed as daily is a twenty-three hour window nobody chose.
func TestTheIntervalReachesTheScheduler(t *testing.T) {
	o := ScheduleOptions{Every: 15 * time.Minute, Binary: "/opt/reeve", Log: "/var/log/d.jsonl", Home: "/home/dev"}
	o.Platform = "linux"
	if !strings.Contains(allText(plan(t, o)), "OnUnitActiveSec=15min") {
		t.Error("linux timer does not seal every 15 minutes")
	}
	o.Platform = "darwin"
	if !strings.Contains(allText(plan(t, o)), "<integer>900</integer>") {
		t.Error("launchd agent does not seal every 900 seconds")
	}
	o.Platform, o.Binary, o.Log = "windows", `C:\r.exe`, `C:\d.jsonl`
	if !strings.Contains(allText(plan(t, o)), "-Minutes 15") {
		t.Error("windows task does not repeat every 15 minutes")
	}
}

// TestRetentionIsPassedOnlyWhenAsked. The free edition keeps everything unless told
// otherwise; a schedule that pruned by default would shorten a record nobody chose to.
func TestRetentionIsPassedOnlyWhenAsked(t *testing.T) {
	o := ScheduleOptions{Platform: "linux", Home: "/home/dev", Binary: "/opt/reeve", Log: "/var/log/d.jsonl"}
	if strings.Contains(allText(plan(t, o)), "--keep") {
		t.Error("rotation prunes without being asked")
	}
	o.Keep = 720 * time.Hour
	if !strings.Contains(allText(plan(t, o)), `"--keep" "720h"`) {
		t.Errorf("--keep 720h did not reach rotate:\n%s", allText(plan(t, o)))
	}
}

// TestAPathThatWouldBeMisreadIsQuotedForItsScheduler. A space or a percent sign in a
// path, unquoted, runs something other than reeve against something other than the log.
func TestAPathThatWouldBeMisreadIsQuotedForItsScheduler(t *testing.T) {
	linux := allText(plan(t, ScheduleOptions{Platform: "linux", Home: "/home/dev",
		Binary: "/opt/my tools/reeve", Log: "/var/log/100%/d.jsonl"}))
	if !strings.Contains(linux, `ExecStart="/opt/my tools/reeve" "audit" "seal" "/var/log/100%%/d.jsonl"`) {
		t.Errorf("systemd line not quoted:\n%s", linux)
	}
	win := allText(plan(t, ScheduleOptions{Platform: "windows",
		Binary: `C:\Users\o'brien\reeve.exe`, Log: `C:\Users\o'brien\d.jsonl`}))
	if !strings.Contains(win, `""C:\Users\o''brien\reeve.exe" "audit" "seal"`) {
		t.Errorf("windows argument not quoted for PowerShell and cmd:\n%s", win)
	}
	mac := allText(plan(t, ScheduleOptions{Platform: "darwin", Home: "/Users/dev",
		Binary: "/opt/r&d/reeve", Log: "/Users/dev/d.jsonl"}))
	if !strings.Contains(mac, "<string>/opt/r&amp;d/reeve</string>") {
		t.Errorf("plist not escaped:\n%s", mac)
	}
}

// TestWhatNoSchedulerCanExpressIsRefused.
func TestWhatNoSchedulerCanExpressIsRefused(t *testing.T) {
	base := ScheduleOptions{Platform: "linux", Home: "/home/dev", Binary: "/opt/reeve", Log: "/var/log/d.jsonl", Every: time.Hour}
	for name, mutate := range map[string]func(*ScheduleOptions){
		"under a minute":      func(o *ScheduleOptions) { o.Every = 30 * time.Second },
		"no interval":         func(o *ScheduleOptions) { o.Every = 0 },
		"negative interval":   func(o *ScheduleOptions) { o.Every = -time.Hour },
		"part of a minute":    func(o *ScheduleOptions) { o.Every = 90 * time.Second },
		"negative retention":  func(o *ScheduleOptions) { o.Keep = -time.Hour },
		"relative log":        func(o *ScheduleOptions) { o.Log = "decisions.jsonl" },
		"relative binary":     func(o *ScheduleOptions) { o.Binary = "./reeve" },
		"windows path, linux": func(o *ScheduleOptions) { o.Log = `C:\d.jsonl` },
		"relative home":       func(o *ScheduleOptions) { o.Home = "dev" },
		"unknown platform":    func(o *ScheduleOptions) { o.Platform = "plan9" },
	} {
		o := base
		mutate(&o)
		if _, err := PlanSchedule(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	w := ScheduleOptions{Platform: "windows", Binary: "/opt/reeve", Log: `C:\d.jsonl`, Every: time.Hour}
	if _, err := PlanSchedule(w); err == nil {
		t.Error("a unix binary path was accepted for windows")
	}
	w.Binary = `\\server\share\reeve.exe`
	if _, err := PlanSchedule(w); err != nil {
		t.Errorf("a UNC path was refused: %v", err)
	}
	m := base
	m.Platform, m.Home = "darwin", "Users/dev"
	if _, err := PlanSchedule(m); err == nil {
		t.Error("a relative darwin home was accepted")
	}
}

func TestShortDurationIsWhatAPersonWouldType(t *testing.T) {
	for d, want := range map[time.Duration]string{
		time.Hour: "1h", 720 * time.Hour: "720h", 30 * time.Minute: "30m",
		90 * time.Minute: "1h30m", time.Hour + 10*time.Second: "1h0m10s",
	} {
		if got := ShortDuration(d); got != want {
			t.Errorf("ShortDuration(%s) = %q, want %q", d, got, want)
		}
	}
}
