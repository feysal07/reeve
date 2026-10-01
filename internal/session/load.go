package session

import (
	"errors"
	"fmt"
	"os"

	"github.com/feysal07/reeve/internal/audit"
	"github.com/feysal07/reeve/internal/replay"
	"github.com/feysal07/reeve/internal/telemetry"
)

// Loaded is what was read, and what could not be.
type Loaded struct {
	Decisions []replay.Record
	Events    []telemetry.Event
	// Read lists every file actually read, rotated segments included, so a timeline
	// assembled from files can say which ones.
	Read []string
	// Notes say what is missing and what that means for the picture, in words.
	Notes []string
}

// Load reads a decision log with every rotated segment still on disk, and an event
// store. Either may be empty; both empty is an error, because a timeline of nothing
// reads exactly like a quiet day.
func Load(logPath, storePath string) (Loaded, error) {
	var l Loaded
	if logPath == "" && storePath == "" {
		return l, fmt.Errorf("give a decision log (--log) or an event store (--store), or both")
	}

	if logPath != "" {
		segs, err := audit.Segments(logPath)
		if err != nil {
			return l, err
		}
		pruned := 0
		// Oldest first, then the live log, so the records come out in the order they
		// were written.
		for _, p := range append(segs, logPath) {
			recs, bad, err := replay.Load(p)
			if errors.Is(err, os.ErrNotExist) {
				if p != logPath {
					pruned++
				}
				continue
			}
			if err != nil {
				return l, err
			}
			l.Decisions = append(l.Decisions, recs...)
			l.Read = append(l.Read, p)
			if bad > 0 {
				l.Notes = append(l.Notes, fmt.Sprintf("%s: %d line(s) could not be read and are "+
					"left out", p, bad))
			}
		}
		if pruned > 0 {
			l.Notes = append(l.Notes, fmt.Sprintf("%d older segment(s) of the decision log were "+
				"removed by retention, so sessions from before them show no guard decisions", pruned))
		}
		if len(l.Read) == 0 {
			l.Notes = append(l.Notes, fmt.Sprintf("the decision log %s does not exist, so no "+
				"session shows what the guard decided", logPath))
		}
	} else {
		l.Notes = append(l.Notes, "no decision log was given, so nothing refused is shown")
	}

	if storePath != "" {
		evs, err := telemetry.ReadEvents(storePath)
		switch {
		case errors.Is(err, os.ErrNotExist):
			l.Notes = append(l.Notes, fmt.Sprintf("the event store %s does not exist, so no "+
				"session shows cost or the tools that ran", storePath))
		case err != nil:
			return l, err
		default:
			l.Events = evs
			l.Read = append(l.Read, storePath)
		}
	} else {
		l.Notes = append(l.Notes, "no event store was given, so no session shows cost or the tools that ran")
	}
	return l, nil
}
