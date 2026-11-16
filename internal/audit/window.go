package audit

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Reading a window of the decision log.
//
// Found on a live machine: report, doctor and the guard's loop-breaker all read the
// live log and nothing else, and the live log is emptied every day by rotation. A
// seven-day report described 105 of about 3,000 decisions and said nothing about the
// rest. Straight after rotation the loop-breaker's history was empty, so a rule that
// counts repeats counted nothing and allowed: the fail-closed rule failed open, every
// morning, on schedule.
//
// So the readers of the log that count read it through here. It visits the rotated
// segments that can hold part of the window, oldest first, then the live log, and it
// says which part of the window it could not see. It refuses nothing itself; the
// caller knows whether a gap is a footnote (a report) or a reason to refuse (a rule
// that counts).

// Window says what a read of the log covered.
type Window struct {
	// Read lists the files visited, oldest first, the live log last when it exists.
	Read []string `json:"read"`
	// Missing lists segments that can hold part of the window and were not read.
	Missing []Gap `json:"missing,omitempty"`
	// Cut lists files whose start was skipped because they were longer than the
	// caller asked to read. Only the caller knows whether that start was inside
	// the window, so it is reported rather than judged.
	Cut []string `json:"cut,omitempty"`
	// LiveExists says the live log was there. Straight after rotation it is not,
	// which means nothing has been decided since, not that anything is missing.
	LiveExists bool `json:"liveExists"`
	// Segments counts every segment found, read or not, so a caller can tell a log
	// that exists only as segments from a path where nothing was ever written.
	Segments int `json:"segments"`
}

// Gap is a segment inside the window whose records could not be read.
type Gap struct {
	Segment string `json:"segment"`
	Why     string `json:"why"`
	// Pruned says retention removed the records, on schedule, and left a tombstone
	// in the segment's chain saying so. A gap all the same, but not a loss.
	Pruned bool `json:"pruned,omitempty"`
}

// Complete reports that every segment that could hold part of the window was read.
func (w Window) Complete() bool { return len(w.Missing) == 0 }

// Part is one file of the log as it is handed to the caller.
type Part struct {
	Path string
	// Live says this is the live log rather than a rotated segment.
	Live bool
	// Cut says the start of the file was skipped; see WindowOptions.MaxBytes.
	Cut bool
}

// WindowOptions bounds a read.
type WindowOptions struct {
	// From is the start of the window. Zero means the whole log.
	From time.Time
	// MaxBytes, when above zero, reads at most this many bytes from the end of each
	// file. The guard sets it: it runs in front of a waiting agent, several agents
	// treat a hook that times out as permission to go ahead, and a file planted in
	// the log's directory, or one that has simply grown, must not be able to make
	// the guard slow enough to be skipped.
	MaxBytes int64
	// Now is when the read happens, for telling a segment stamped in the future.
	// Zero means time.Now().
	Now time.Time
}

// futureSkew is how far ahead of the clock a segment's stamp may be before it is
// treated as not one this machine's rotation wrote.
const futureSkew = 5 * time.Minute

// inFlight is how recently a segment must have been stamped for its records being
// absent to be read as a rotation still moving them rather than as records lost.
const inFlight = 10 * time.Second

// rotating reports that seg is a rotation still in progress: its chain has moved, its
// records have not, and the live log has no chain of its own yet. Rotate writes the
// live log's new chain last, so once it exists the rotation is over and a segment
// with no records is records lost, however recent. Found by the test that deletes a
// segment straight after rotating: judged by age alone, that deletion was hidden.
func rotating(logPath, seg string, now time.Time) bool {
	if _, err := os.Stat(ChainPath(logPath)); !errors.Is(err, os.ErrNotExist) {
		return false
	}
	t, ok := segmentStamp(logPath, seg)
	return ok && now.Sub(t) < inFlight
}

// Test hooks for the rotation race. Nil outside tests.
var rotateBetween, rotateAfterOpen func()

type openFile struct {
	path string
	f    *os.File
}

// ReadWindow visits every file of the log that can hold records from from onwards,
// oldest first. A zero from means the whole log, every segment still on disk.
func ReadWindow(logPath string, from time.Time, visit func(p Part, r io.Reader) error) (Window, error) {
	return ReadWindowWith(logPath, WindowOptions{From: from}, visit)
}

// ReadWindowWith is ReadWindow with a bound on how much of each file is read.
//
// A segment is named by when it was rotated and holds what was written before then, so
// one rotated before the window began cannot hold any of it and is passed over. One
// that can, and whose records are gone or cannot be opened, is a gap, not an error. A
// live log that exists and cannot be opened is an error: it is the part of the window
// most likely to matter, and a caller that cannot tell it apart from an empty one
// would read "could not look" as "nothing happened".
func ReadWindowWith(logPath string, o WindowOptions, visit func(p Part, r io.Reader) error) (Window, error) {
	var w Window
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	var files []openFile
	defer func() {
		for _, of := range files {
			of.f.Close()
		}
	}()

	seen := map[string]bool{}
	// retry holds segments whose records were not there when first looked for.
	// Rotate moves a segment's chain before its records, so a listing that lands
	// between the two finds a segment whose records arrive a moment later. Found
	// in review: recorded as missing straight away, that was a gap in the window,
	// and a refusal, once a day for no reason.
	var retry []string
	add := func(seg string, retrying bool) {
		seen[seg] = true
		t, _ := segmentStamp(logPath, seg)
		if !o.From.IsZero() && t.Before(o.From) {
			return
		}
		if t.After(now.Add(futureSkew)) {
			// Not one this machine's rotation wrote: rotation stamps a segment
			// with the time it ran. Read, it would always fall inside every
			// window, and sorting after every real segment, its contents would
			// decide where the walk back through the window stops.
			w.Missing = append(w.Missing, Gap{Segment: seg, Why: "it is stamped " +
				t.Format(time.RFC3339) + ", in the future, so it was not written by rotation here"})
			return
		}
		f, err := openRegular(seg)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && !retrying {
				retry = append(retry, seg)
				return
			}
			why, pruned := whyUnread(seg, err)
			w.Missing = append(w.Missing, Gap{Segment: seg, Why: why, Pruned: pruned})
			return
		}
		files = append(files, openFile{seg, f})
	}

	segs, err := findSegments(logPath)
	if err != nil {
		return w, err
	}
	for _, s := range segs {
		add(s, false)
	}

	if rotateBetween != nil {
		rotateBetween()
	}
	live, err := openRegular(logPath)
	switch {
	case err == nil:
		w.LiveExists = true
		defer live.Close()
	case errors.Is(err, os.ErrNotExist):
	default:
		return w, fmt.Errorf("%s cannot be read: %w", logPath, err)
	}
	if rotateAfterOpen != nil {
		rotateAfterOpen()
	}

	// Listed again, because the log may have rotated since the first listing. Found
	// in review: the segments were listed and then the live log opened, so a rotation
	// between the two moved the records that were live into a segment nobody had
	// listed, and handed back a fresh live log with nothing in it. A segment that has
	// appeared since is read, unless it is the very file already open as the live log,
	// which a rotation just after opening it produces, and which would count twice.
	again, err := findSegments(logPath)
	if err != nil {
		return w, err
	}
	var liveInfo os.FileInfo
	if live != nil {
		if liveInfo, err = live.Stat(); err != nil {
			// Without it the rotated copy of the live log cannot be told from the
			// live log, and would be counted twice.
			return w, fmt.Errorf("%s cannot be read: %w", logPath, err)
		}
	}
	isLive := func(seg string) bool {
		info, err := os.Stat(seg)
		return err == nil && liveInfo != nil && os.SameFile(info, liveInfo)
	}
	for _, s := range again {
		if seen[s] {
			continue
		}
		if _, err := os.Stat(s); errors.Is(err, os.ErrNotExist) {
			// Its chain has moved and its records have not yet: the records are
			// still in the live log, which is open.
			continue
		}
		if isLive(s) {
			continue
		}
		add(s, true)
	}
	for _, s := range retry {
		if isLive(s) {
			continue // the records the listing missed are the live log being read
		}
		if _, err := os.Stat(s); errors.Is(err, os.ErrNotExist) && live != nil && rotating(logPath, s, now) {
			// Still not there, and a rotation is still moving it: the records are
			// in the live log already open.
			continue
		}
		add(s, true)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	w.Segments = max(len(segs), len(again))

	read := func(path string, f *os.File, isLive bool) error {
		p := Part{Path: path, Live: isLive}
		r, cut, err := tail(f, o.MaxBytes)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if cut {
			p.Cut = true
			w.Cut = append(w.Cut, path)
		}
		if err := visit(p, r); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		w.Read = append(w.Read, path)
		return nil
	}
	for _, of := range files {
		if err := read(of.path, of.f, false); err != nil {
			return w, err
		}
	}
	if live != nil {
		if err := read(logPath, live, true); err != nil {
			return w, err
		}
	}
	return w, nil
}

// tail positions f to read at most max bytes from its end, starting at a line.
func tail(f *os.File, max int64) (io.Reader, bool, error) {
	if max <= 0 {
		return f, false, nil
	}
	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if info.Size() <= max {
		return f, false, nil
	}
	if _, err := f.Seek(info.Size()-max, io.SeekStart); err != nil {
		return nil, false, err
	}
	br := bufio.NewReader(f)
	// The first line is almost certainly a fragment of one that began earlier.
	if _, err := br.ReadString('\n'); err != nil && err != io.EOF {
		return nil, false, err
	}
	return br, true, nil
}

// openRegular opens a file of the log for reading, refusing anything but a regular
// file.
//
// Found in review: segments are found by name in a directory the agent can write to,
// so a FIFO named as a segment blocked the guard's open for ever, and a link to
// /dev/urandom handed it an endless stream of short lines. Either way the hook ran
// until the agent's timeout, and several agents treat a hook that times out as
// permission to go ahead: a one-command way past the guard.
func openRegular(path string) (*os.File, error) {
	f, err := openNonBlocking(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return f, nil
}

// findSegments lists the log's segments by their records and by their chains, oldest
// first.
//
// Segments lists by chain, which is right for retention and verify: a segment is its
// chain once its records are pruned. For reading it is not enough. Found in review: a
// segment whose chain had gone, lost or deleted, was invisible here, so its records
// were neither read nor reported missing, and the window read as complete with them
// left out. Listing the directory also avoids building a glob from the log's path,
// which mangled a path holding a backslash on Unix, where Glob reads it as an escape.
func findSegments(logPath string) ([]string, error) {
	dir := filepath.Dir(logPath)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ChainSuffix)
		seg := filepath.Join(dir, name)
		if _, ok := segmentStamp(logPath, seg); ok {
			found[seg] = true
		}
	}
	out := make([]string, 0, len(found))
	for s := range found {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

// segmentStamp is when a segment was rotated, read from its name.
func segmentStamp(logPath, seg string) (time.Time, bool) {
	ext := filepath.Ext(logPath)
	prefix := filepath.Base(strings.TrimSuffix(logPath, ext)) + segmentSeparator
	name := filepath.Base(seg)
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ext) {
		return time.Time{}, false
	}
	stamp := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ext)
	t, err := time.Parse(stampLayout, stamp)
	return t, err == nil
}

// whyUnread says why a segment's records were not read, in words a report can print.
//
// Retention is told apart from deletion by the tombstone retention leaves in the
// segment's chain. Saying "missing" for a segment retention pruned would make routine
// housekeeping read as tampering; saying "pruned" for one somebody deleted would do the
// reverse, which is worse.
func whyUnread(seg string, err error) (why string, pruned bool) {
	if !errors.Is(err, os.ErrNotExist) {
		return "it cannot be read: " + err.Error(), false
	}
	seals, cerr := ReadSeals(ChainPath(seg))
	switch {
	case cerr != nil && errors.Is(cerr, os.ErrNotExist):
		return "its records and its chain are missing", false
	case cerr != nil:
		return "its records are missing, and its chain cannot be read: " + cerr.Error(), false
	case len(seals) > 0 && seals[len(seals)-1].Pruned:
		return "its records were removed by retention", true
	}
	return "its records are missing", false
}
