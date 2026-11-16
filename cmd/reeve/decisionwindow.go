package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/feysal07/reeve/internal/audit"
	"github.com/feysal07/reeve/internal/telemetry"
)

// decisionWindow is what was read of one decision log for a report.
type decisionWindow struct {
	Events []telemetry.Event
	// Unread names segments inside the window whose records are missing or could not
	// be read, with why. What the guard decided is undercounted by them.
	Unread []string
	// Pruned names segments inside the window whose records retention removed on
	// schedule. Routine, and said apart from Unread so that it does not train anyone
	// to skim past the line that matters.
	Pruned []string
}

// readDecisionWindow reads every rotated segment of a decision log inside the window,
// then the live log, as events.
//
// Found on a live machine: reading the live log alone, a seven-day report saw 105 of
// about 3,000 decisions, because rotation empties it every day, and said nothing.
func readDecisionWindow(path string, from time.Time) (decisionWindow, error) {
	var d decisionWindow
	// A directory given as the log is refused here with the file it holds named,
	// rather than as a read error from deep in the window. A live log that does not
	// exist is not refused yet: straight after rotation its segments are the whole
	// of the log.
	if err := telemetry.CheckDecisionLog(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return d, err
	}
	w, err := audit.ReadWindow(path, from, func(_ audit.Part, r io.Reader) error {
		e, err := telemetry.DecodeDecisions(r)
		d.Events = append(d.Events, e...)
		return err
	})
	if err != nil {
		return d, err
	}
	if !w.LiveExists && w.Segments == 0 {
		// Nothing at all under that name. A mistyped path must stay an error rather
		// than become a report of a machine where nothing happened.
		return d, telemetry.CheckDecisionLog(path)
	}
	for _, g := range w.Missing {
		line := filepath.Base(g.Segment) + ": " + g.Why
		if g.Pruned {
			d.Pruned = append(d.Pruned, line)
			continue
		}
		d.Unread = append(d.Unread, line)
	}
	return d, nil
}
