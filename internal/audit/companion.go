package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// A companion log is one written beside the decision log and read with it, such as the
// outcome log, which records whether an asked action ran. It is not sealed, so it has no
// chain, but it lives and dies with the decision log.
//
// Found in the v0.7.0 audit: the outcome log was never rotated or pruned, so it grew for
// ever, and retention that removed a month-old decision kept every outcome of it. A
// report over a window then joined today's asks against an ever-longer file, and the
// promise of thirty days' retention was kept for one file and not its neighbour.

// CompanionSegmentPath is where a companion log goes when rotated at t: the same
// stamp a decision log rotated at t gets, so a window reads the two together.
func CompanionSegmentPath(companion string, t time.Time) string {
	return segmentPath(companion, t)
}

// RotateCompanionAt moves a companion log aside under the stamp t. It returns where it
// went, or "" when there was none to move, which is a machine where nothing writes one.
//
// The caller checks CompanionSegmentPath before rotating the decision log, so that a
// clash refuses before anything has moved; the check here is the second line, and on
// every platform Rename would otherwise replace whatever was there.
func RotateCompanionAt(companion string, t time.Time) (string, error) {
	dest := segmentPath(companion, t)
	if _, err := os.Lstat(dest); err == nil {
		return "", fmt.Errorf("not rotated: %s already exists", dest)
	}
	if err := os.Rename(companion, dest); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("%s could not be moved aside, perhaps because a guard is "+
			"writing to it; the next rotation tries again: %w", filepath.Base(companion), err)
	}
	return dest, nil
}

// PruneCompanion removes a companion's segments rotated longer ago than keep, the same
// schedule retention applies to the decision log. Keep zero keeps everything.
//
// Only regular files are removed, and only those reported. Found in review: a directory
// named like an old segment failed its removal and, oldest first, stopped every later
// segment being pruned; and a chain-shaped name with no records was reported as pruned
// when nothing had been removed. Every failure is returned, after the rest are tried.
func PruneCompanion(companion string, now time.Time, keep time.Duration) ([]string, error) {
	if keep <= 0 {
		return nil, nil
	}
	segs, err := findSegments(companion)
	if err != nil {
		return nil, err
	}
	cutoff := now.Add(-keep)
	var pruned []string
	var failed []error
	for _, s := range segs {
		t, ok := segmentStamp(companion, s)
		if !ok || !t.Before(cutoff) {
			continue
		}
		info, err := os.Lstat(s)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if err := os.Remove(s); err != nil {
			failed = append(failed, err)
			continue
		}
		pruned = append(pruned, filepath.Base(s))
	}
	return pruned, errors.Join(failed...)
}
