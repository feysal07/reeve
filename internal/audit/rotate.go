package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Rotation and retention.
//
// A decision log that is never rotated grows for ever, and a free tier that promises
// thirty days of retention has to be able to forget day thirty-one. The difficulty is
// the seals: delete the first half of a sealed log and every seal fails, which is
// exactly what tampering looks like. Retention that cannot be told apart from tampering
// is retention nobody can use, or tampering anybody can explain away.
//
// So rotation works in whole segments. The current log is sealed, then moved aside with
// its chain; the new log's chain begins with a seal of nothing that names the segment
// it follows and carries the hash of that segment's last seal. The chains are therefore
// one chain across files. Retention then deletes a segment's records and keeps its
// chain, which is a few hundred bytes of counts, times and hashes: enough for verify to
// say "pruned on schedule" rather than "missing", and to prove the segments that remain
// still join up. Deleting a chain as well breaks that link, and verify says so.

// segmentSeparator sits between a log's name and its rotation stamp.
const segmentSeparator = "-"

// stampLayout names a segment by when it was rotated, in UTC, sortable as text. To the
// millisecond: found by the walkthrough, two rotations inside one second named the same
// segment, and the second refused.
const stampLayout = "20060102T150405.000Z"

// segmentPath is where a log is moved to when it is rotated at t.
func segmentPath(logPath string, t time.Time) string {
	ext := filepath.Ext(logPath)
	base := strings.TrimSuffix(logPath, ext)
	return base + segmentSeparator + t.UTC().Format(stampLayout) + ext
}

// Segments lists a log's rotated segments, oldest first, including those whose records
// retention has removed and only the chain remains.
func Segments(logPath string) ([]string, error) {
	ext := filepath.Ext(logPath)
	base := strings.TrimSuffix(logPath, ext)
	chains, err := filepath.Glob(globEscape(base+segmentSeparator) + "*" + globEscape(ext+ChainSuffix))
	if err != nil {
		return nil, err
	}
	var out []string
	prefix := filepath.Base(base) + segmentSeparator
	for _, c := range chains {
		seg := strings.TrimSuffix(c, ChainSuffix)
		// Compared on base names. Found by the walkthrough: Glob hands back paths in
		// the platform's separators, so a log named with forward slashes on Windows
		// never matched its own segments' prefix, every segment was skipped, and
		// retention silently removed nothing while reporting success.
		stamp := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(seg), prefix), ext)
		if _, err := time.Parse(stampLayout, stamp); err != nil {
			continue
		}
		out = append(out, seg)
	}
	sort.Strings(out)
	return out, nil
}

func globEscape(s string) string {
	r := strings.NewReplacer("[", "[[]", "*", "[*]", "?", "[?]")
	return r.Replace(s)
}

// Rotation says what Rotate did.
type Rotation struct {
	// Segment is where the log was moved, empty when there was nothing to rotate.
	Segment string `json:"segment,omitempty"`
	Lines   int64  `json:"lines"`
	// Pruned are segments whose records retention removed in this run.
	Pruned []string `json:"pruned,omitempty"`
	// Kept are segments that were old enough to prune and were not, with why.
	Kept []string `json:"kept,omitempty"`
}

// Rotate seals the log, moves it aside with its chain, and starts the next chain linked
// to it. With keep above zero it then prunes segments rotated longer ago than keep.
//
// Sealing first is the whole safety argument. Add refuses a log whose sealed part has
// changed, so a log that has been tampered with cannot be rotated into a clean-looking
// segment; the refusal surfaces here, where somebody is looking.
func Rotate(logPath string, now time.Time, keep time.Duration, version string) (Rotation, error) {
	var rot Rotation
	_, lines, err := Hash(logPath, 0)
	switch {
	case errors.Is(err, os.ErrNotExist):
		lines = 0
	case err != nil:
		return rot, err
	}

	if lines > 0 {
		// Checked before sealing, so a rotation that cannot happen leaves no seal
		// behind to say it did.
		seg := segmentPath(logPath, now)
		if _, err := os.Stat(seg); err == nil {
			return rot, fmt.Errorf("not rotated: %s already exists", seg)
		}
		last, err := Add(logPath, now, version)
		if err != nil {
			return rot, fmt.Errorf("not rotated: %w", err)
		}
		// The chain moves first. If the log's move then fails, the chain is put back
		// and nothing has changed; the other order could leave records sealed by
		// nothing.
		if err := os.Rename(ChainPath(logPath), ChainPath(seg)); err != nil {
			return rot, fmt.Errorf("not rotated: %w", err)
		}
		if err := os.Rename(logPath, seg); err != nil {
			_ = os.Rename(ChainPath(seg), ChainPath(logPath))
			return rot, fmt.Errorf("not rotated: the log could not be moved, perhaps because "+
				"a guard is writing to it; nothing was changed: %w", err)
		}
		if err := startChain(logPath, seg, last, now, version); err != nil {
			return rot, fmt.Errorf("rotated to %s, but the new chain could not be started, so "+
				"the next segment will not be linked to it: %w", seg, err)
		}
		rot.Segment, rot.Lines = seg, lines
	}

	if keep > 0 {
		pruned, kept, err := prune(logPath, now.Add(-keep))
		rot.Pruned, rot.Kept = pruned, kept
		if err != nil {
			return rot, err
		}
	}
	return rot, nil
}

// startChain writes the first seal of a new log: nothing yet, following seg.
func startChain(logPath, seg string, last Seal, now time.Time, version string) error {
	prevLine, err := json.Marshal(last)
	if err != nil {
		return err
	}
	s := Seal{
		SealedAt: now.UTC(),
		Lines:    0,
		Hash:     newRunningHash().digest(),
		Prev:     sealLineHash(prevLine),
		Version:  version,
		Follows:  filepath.Base(seg),
	}
	body, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(ChainPath(logPath), append(body, '\n'), 0o600)
}

// prune removes the records of segments rotated before cutoff, and keeps their chains.
//
// A segment that does not verify is not pruned. Deleting it would destroy the only
// evidence of whatever changed it, on a schedule, with a message saying retention did
// it.
func prune(logPath string, cutoff time.Time) (pruned, kept []string, err error) {
	segs, err := Segments(logPath)
	if err != nil {
		return nil, nil, err
	}
	for _, seg := range segs {
		if _, err := os.Stat(seg); errors.Is(err, os.ErrNotExist) {
			continue // already pruned
		}
		seals, err := ReadSeals(ChainPath(seg))
		if err != nil || len(seals) == 0 {
			kept = append(kept, filepath.Base(seg)+": its chain cannot be read, so it is not pruned")
			continue
		}
		if !seals[len(seals)-1].SealedAt.Before(cutoff) {
			continue
		}
		rep, err := verifyOne(seg)
		if err != nil || !rep.Intact() || rep.Unsealed > 0 {
			kept = append(kept, filepath.Base(seg)+": it does not verify, so it is not pruned; "+
				"run reeve audit verify on it")
			continue
		}
		if err := os.Remove(seg); err != nil {
			return pruned, kept, err
		}
		pruned = append(pruned, filepath.Base(seg))
	}
	return pruned, kept, nil
}

// SegmentStatus is one earlier segment as verify found it.
type SegmentStatus struct {
	Segment string `json:"segment"`
	// State is intact, pruned, broken or missing.
	State  string `json:"state"`
	Lines  int64  `json:"lines,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// verifyHistory walks back from a log through the segments it follows.
func verifyHistory(logPath string, seals []Seal) ([]SegmentStatus, []Break) {
	var out []SegmentStatus
	var breaks []Break
	dir := filepath.Dir(logPath)
	for len(seals) > 0 && seals[0].Follows != "" {
		first := seals[0]
		seg := filepath.Join(dir, first.Follows)
		prev, err := ReadSeals(ChainPath(seg))
		if err != nil || len(prev) == 0 {
			out = append(out, SegmentStatus{Segment: first.Follows, State: "missing",
				Detail: "its chain is gone, so nothing shows what it held or that it was pruned rather than deleted"})
			breaks = append(breaks, Break{SealedAt: first.SealedAt,
				Detail: fmt.Sprintf("the segment this log follows, %s, is missing along with its chain", first.Follows)})
			break
		}
		prevLine, err := json.Marshal(prev[len(prev)-1])
		if err == nil && sealLineHash(prevLine) != first.Prev {
			breaks = append(breaks, Break{SealedAt: first.SealedAt,
				Detail: fmt.Sprintf("the first seal after %s does not follow its last seal: "+
					"a segment has been replaced or its chain rewritten", first.Follows)})
		}
		st := SegmentStatus{Segment: first.Follows, Lines: prev[len(prev)-1].Lines}
		if _, err := os.Stat(seg); errors.Is(err, os.ErrNotExist) {
			st.State = "pruned"
			st.Detail = fmt.Sprintf("records removed by retention; %d lines were sealed through %s",
				st.Lines, prev[len(prev)-1].SealedAt.Format(time.RFC3339))
		} else if rep, err := verifyOne(seg); err != nil || !rep.Intact() {
			st.State = "broken"
			st.Detail = "does not verify; run reeve audit verify on it"
			breaks = append(breaks, Break{SealedAt: prev[len(prev)-1].SealedAt,
				Detail: fmt.Sprintf("the earlier segment %s does not verify", first.Follows)})
		} else {
			st.State = "intact"
		}
		out = append(out, st)
		seals = prev
	}
	return out, breaks
}
