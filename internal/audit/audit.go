// Package audit makes the decision log tamper-evident.
//
// The decision log is the half of the record no vendor can supply: an action the guard
// refused never happened as far as the agent is concerned, so nothing else anywhere
// has a trace of it. That makes it the most valuable file this tool produces and the
// most worth editing, and until now the only answer to "how do you know these were not
// changed afterwards" was to trust the file.
//
// # Why this seals rather than chaining each line as it is written
//
// The obvious design is a hash in every record linking it to the one before. It does
// not survive contact with how the log is actually written, for two reasons.
//
// Every guard invocation is a separate short-lived process appending with O_APPEND and
// no lock. Agents run tools concurrently, so two processes would read the same last
// line and write two records claiming the same predecessor. That is a forked chain,
// and a verifier cannot tell a fork caused by ordinary concurrency from one caused by
// an inserted record. A tamper detector that cries tamper on a busy machine is a
// tamper detector nobody runs twice.
//
// And the guard must be fast. Agents time hooks out and several of them treat a
// timeout as permission to continue, so anything that makes the hot path read the tail
// of a growing file, or worse wait on a lock, trades enforcement for evidence.
//
// Sealing separates the two. The guard keeps appending exactly as it did, at exactly
// the same cost. A separate command periodically records how many lines the log had
// and what they hashed to, in a sidecar whose own entries chain to each other. Nothing
// is added to the hot path and there is no concurrency to lose.
//
// # What a seal proves, and what it does not
//
// Between two seals, it proves that no line was changed, inserted or removed: the
// running hash covers every byte in order, and the line count is recorded, so deleting
// from the end is caught as well as editing in the middle. Having several seals over
// time localises a break to the interval between two of them rather than only saying
// that something, somewhere, changed.
//
// It does not protect anything written since the last seal, and it cannot. It also
// does not stop anyone from editing the log and re-sealing: the sidecar is evidence
// only to the extent that it is harder to reach than the log, so copy it somewhere the
// machine cannot write. That is a property of where you put it, not of this code, and
// saying otherwise would be the kind of claim this tool exists to catch.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ChainSuffix is appended to a log's path to find its sidecar.
const ChainSuffix = ".chain"

// genesis starts every running hash.
//
// A constant rather than an empty hash, so that the digest of an empty log is a value
// specific to this format and version rather than the digest of nothing, which is a
// well-known constant that could be produced by accident.
var genesis = []byte("reeve-audit-v1")

// Seal is one record of what the log contained at one moment.

// SchemaVersion is the shape of the JSON this package emits.
//
// One form across every command: a string such as "1.0", matching scan and
// posture. The report used an int for one release, so a consumer reading
// schemaVersion got a number from one command and a string from another and had
// to type-switch on a field whose whole purpose is to be checked first.
const SchemaVersion = "1.0"

type Seal struct {
	SealedAt time.Time `json:"sealedAt"`
	// Lines is how many lines the log held when this seal was taken.
	Lines int64 `json:"lines"`
	// Hash is the running hash over those lines, in order.
	Hash string `json:"hash"`
	// Prev is the hash of the preceding seal line, so the sidecar is itself a
	// chain. Without it, a seal could be removed to hide the interval it covered.
	Prev string `json:"prev,omitempty"`
	// Version records which build wrote the seal, so a future change to the hash
	// construction can be told apart from a mismatch.
	Version string `json:"version,omitempty"`
	// Follows names the segment this log was rotated from, on the first seal of a
	// rotated log only. Prev on that seal is the hash of the segment's last seal, so
	// the chains of every segment are one chain. See rotate.go.
	Follows string `json:"follows,omitempty"`
}

// ChainPath returns the sidecar path for a log.
func ChainPath(logPath string) string { return logPath + ChainSuffix }

// runningHash is the chain over a log's lines.
//
// h(0) is the genesis constant. h(i) is the digest of h(i-1) followed by line i. The
// previous digest is mixed in rather than the lines being concatenated, so that
// re-ordering two lines changes the result, and so a prefix of the log can be verified
// against an earlier seal without rereading anything twice.
type runningHash struct {
	h     hash.Hash
	state []byte
	lines int64
}

func newRunningHash() *runningHash {
	return &runningHash{h: sha256.New(), state: genesis}
}

func (r *runningHash) add(line []byte) {
	r.h.Reset()
	r.h.Write(r.state)
	r.h.Write([]byte{0})
	r.h.Write(line)
	r.state = r.h.Sum(nil)
	r.lines++
}

func (r *runningHash) digest() string { return "sha256:" + hex.EncodeToString(r.state) }

// scanner returns a line scanner sized for decision records, which carry a reason and
// can be long.
func scanner(rd io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	return sc
}

// Hash computes the running hash of a log, and the number of lines it holds.
//
// stopAt bounds the read to that many lines, for checking a log against a seal taken
// when it was shorter. Zero means the whole file. The returned count is how many lines
// were actually hashed, which is less than stopAt when the log is shorter than the
// seal claims: that is itself the finding.
func Hash(logPath string, stopAt int64) (digest string, lines int64, err error) {
	f, err := os.Open(logPath)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	r := newRunningHash()
	sc := scanner(f)
	for sc.Scan() {
		if stopAt > 0 && r.lines == stopAt {
			break
		}
		r.add(sc.Bytes())
	}
	if err := sc.Err(); err != nil {
		return "", 0, err
	}
	return r.digest(), r.lines, nil
}

// ReadSeals loads a sidecar. A missing sidecar is not an error: it means the log has
// never been sealed, which is a state to report rather than a failure.
func ReadSeals(chainPath string) ([]Seal, error) {
	f, err := os.Open(chainPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var seals []Seal
	sc := scanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var s Seal
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			return nil, fmt.Errorf("%s line %d is not a seal: %w", chainPath, n, err)
		}
		seals = append(seals, s)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return seals, nil
}

// sealLineHash digests one seal line as written, so the next seal can chain to it.
func sealLineHash(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Add seals a log: records its current length and hash, chained to the previous seal.
//
// Appending rather than replacing. The history of seals is what allows a break to be
// localised to an interval, and it is also what makes removing a seal visible, since
// the next one names it.
func Add(logPath string, now time.Time, version string) (Seal, error) {
	chainPath := ChainPath(logPath)
	seals, err := ReadSeals(chainPath)
	if err != nil {
		return Seal{}, err
	}
	digest, lines, err := hashOrEmpty(logPath, len(seals) > 0)
	if err != nil {
		return Seal{}, err
	}

	// Sealing a log that has become shorter, or whose sealed prefix no longer
	// hashes the same, would write a seal that silently blesses the new content and
	// destroy the evidence the sidecar existed to hold.
	if n := len(seals); n > 0 {
		last := seals[n-1]
		if lines < last.Lines {
			return Seal{}, fmt.Errorf(
				"refusing to seal: the log has %d lines and the last seal covered %d. "+
					"Lines have been removed since %s. Run `reeve audit verify` and keep "+
					"the current %s before doing anything else",
				lines, last.Lines, last.SealedAt.Format(time.RFC3339), filepath.Base(chainPath))
		}
		prefix, err := prefixHash(logPath, last.Lines)
		if err != nil {
			return Seal{}, err
		}
		if prefix != last.Hash {
			return Seal{}, fmt.Errorf(
				"refusing to seal: the first %d lines no longer match the seal taken at %s. "+
					"Something in the already-sealed part of this log has changed. Run "+
					"`reeve audit verify`",
				last.Lines, last.SealedAt.Format(time.RFC3339))
		}
	}

	s := Seal{
		SealedAt: now.UTC(),
		Lines:    lines,
		Hash:     digest,
		Version:  version,
	}
	if n := len(seals); n > 0 {
		prevLine, err := json.Marshal(seals[n-1])
		if err != nil {
			return Seal{}, err
		}
		s.Prev = sealLineHash(prevLine)
	}

	body, err := json.Marshal(s)
	if err != nil {
		return Seal{}, err
	}
	if err := os.MkdirAll(filepath.Dir(chainPath), 0o755); err != nil {
		return Seal{}, err
	}
	f, err := os.OpenFile(chainPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return Seal{}, err
	}
	defer f.Close()
	if _, err := f.Write(append(body, '\n')); err != nil {
		return Seal{}, err
	}
	return s, nil
}

// Report is the outcome of verifying a log against its seals.
type Report struct {
	// SchemaVersion is the shape of this document, following the same convention as
	// every other JSON this binary emits.
	SchemaVersion string `json:"schemaVersion"`
	LogPath       string `json:"logPath"`
	ChainPath     string `json:"chainPath"`
	// Lines is how many lines the log holds now.
	Lines int64 `json:"lines"`
	Seals int   `json:"seals"`
	// Verified states the conclusion rather than leaving it to be inferred from an
	// empty list of breaks.
	Verified bool `json:"verified"`
	// SealedThrough is the line count of the last seal that verified. Everything up
	// to it is covered and unchanged.
	SealedThrough int64 `json:"sealedThrough"`
	// Unsealed is how many lines were written after the last seal was taken.
	//
	// Measured against the last seal taken and not the last one that passed. Those
	// are the same number on an intact log and very different on a broken one: a
	// failed seal does not turn the lines it covered into lines nobody has sealed,
	// and reporting it that way would describe tampering as though it were a
	// scheduling gap.
	Unsealed int64 `json:"unsealed"`
	// Breaks are the intervals that failed, in order. More than one is possible.
	Breaks []Break `json:"breaks,omitempty"`
	// History is every earlier segment this log was rotated from, newest first, as
	// far back as the chains go. A pruned segment is reported as pruned, not missing.
	History []SegmentStatus `json:"history,omitempty"`
}

// Break is one interval of the log that no longer matches what was sealed.
type Break struct {
	// FromLine and ToLine bound the interval. The change is somewhere inside it;
	// a hash says that something differs, not which line.
	FromLine int64     `json:"fromLine"`
	ToLine   int64     `json:"toLine"`
	SealedAt time.Time `json:"sealedAt"`
	Detail   string    `json:"detail"`
}

// Intact reports whether this log is proven unaltered.
//
// It requires at least one seal, and not merely the absence of breaks. A log that has
// never been sealed has nothing to contradict, so "no breaks found" is true of it and
// means nothing at all — which is the most convincing possible way to report that a
// control was never switched on. The distinction matters most to whatever reads the
// JSON, where a missing "breaks" array is otherwise indistinguishable from a pass.
func (r Report) Intact() bool { return r.Seals > 0 && len(r.Breaks) == 0 }

// Verify checks a log against its sidecar.
//
// Seals are checked in order and each failure is reported rather than stopping at the
// first, because the interval between the last good seal and the first bad one is what
// localises a change, and later seals still carry information about later intervals.
func Verify(logPath string) (Report, error) {
	rep, err := verifyOne(logPath)
	if err != nil {
		return rep, err
	}
	seals, err := ReadSeals(rep.ChainPath)
	if err != nil {
		return rep, err
	}
	history, breaks := verifyHistory(logPath, seals)
	rep.History = history
	rep.Breaks = append(rep.Breaks, breaks...)
	rep.Verified = rep.Intact()
	return rep, nil
}

// hashOrEmpty hashes a log, reading a log that does not exist as an empty one when the
// caller knows it has been sealed before - which is the state straight after rotation,
// before the guard has written the first line of the new log. Without a chain a missing
// log stays an error: a path that names nothing is a mistake to report, not a log.
func hashOrEmpty(logPath string, sealed bool) (string, int64, error) {
	digest, lines, err := Hash(logPath, 0)
	if err != nil && sealed && os.IsNotExist(err) {
		return newRunningHash().digest(), 0, nil
	}
	return digest, lines, err
}

// prefixHash is the hash of a log's first n lines. Hash reads zero as "the whole file",
// so a seal of nothing - the first seal of a rotated log - is answered here instead.
func prefixHash(logPath string, n int64) (string, error) {
	if n == 0 {
		return newRunningHash().digest(), nil
	}
	digest, _, err := Hash(logPath, n)
	return digest, err
}

// verifyOne checks one log against its own chain, without following earlier segments.
func verifyOne(logPath string) (Report, error) {
	rep := Report{SchemaVersion: SchemaVersion, LogPath: logPath, ChainPath: ChainPath(logPath)}

	seals, err := ReadSeals(rep.ChainPath)
	if err != nil {
		return rep, err
	}
	_, lines, err := hashOrEmpty(logPath, len(seals) > 0)
	if err != nil {
		return rep, err
	}
	rep.Lines = lines
	rep.Seals = len(seals)
	if len(seals) == 0 {
		rep.Unsealed = lines
		return rep, nil
	}

	// The sidecar's own chain first. A seal that does not name its predecessor
	// correctly means a seal was removed or rewritten, which would otherwise let
	// someone drop the seal covering the interval they edited.
	for i := 1; i < len(seals); i++ {
		prevLine, err := json.Marshal(seals[i-1])
		if err != nil {
			return rep, err
		}
		if want := sealLineHash(prevLine); seals[i].Prev != want {
			rep.Breaks = append(rep.Breaks, Break{
				FromLine: seals[i-1].Lines,
				ToLine:   seals[i].Lines,
				SealedAt: seals[i].SealedAt,
				Detail: fmt.Sprintf("seal %d does not follow seal %d: a seal has been "+
					"removed or rewritten, which is how the record of an edited interval "+
					"would be hidden", i+1, i),
			})
		}
	}

	var lastGood int64
	for i, s := range seals {
		var digest string
		var got int64
		if s.Lines == 0 {
			digest = newRunningHash().digest()
		} else if digest, got, err = Hash(logPath, s.Lines); err != nil {
			return rep, err
		}
		switch {
		case got < s.Lines:
			rep.Breaks = append(rep.Breaks, Break{
				FromLine: got,
				ToLine:   s.Lines,
				SealedAt: s.SealedAt,
				Detail: fmt.Sprintf("the log holds %d lines and this seal covered %d, so "+
					"%d have been removed from the end", got, s.Lines, s.Lines-got),
			})
		case digest != s.Hash:
			rep.Breaks = append(rep.Breaks, Break{
				FromLine: lastGood + 1,
				ToLine:   s.Lines,
				SealedAt: s.SealedAt,
				Detail: fmt.Sprintf("lines %d to %d no longer hash to what seal %d recorded",
					lastGood+1, s.Lines, i+1),
			})
		default:
			lastGood = s.Lines
			rep.SealedThrough = s.Lines
		}
	}

	var covered int64
	for _, s := range seals {
		if s.Lines > covered {
			covered = s.Lines
		}
	}
	if lines > covered {
		rep.Unsealed = lines - covered
	}
	rep.Verified = rep.Intact()
	return rep, nil
}
