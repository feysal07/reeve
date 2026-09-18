package telemetry

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// A minimal protobuf wire-format reader.
//
// Reeve decodes about a dozen OTLP message types. Depending on the generated
// OpenTelemetry protobuf packages to do that costs five megabytes of binary, a 44%
// increase, for code that is mostly service stubs and gRPC gateway plumbing Reeve
// never calls. For a tool meant to be dropped on every developer machine and CI
// runner, that is poor value.
//
// The risk of hand-rolling is a decoder that is subtly wrong and silently drops
// telemetry, which is exactly the class of failure this project exists to catch. That
// risk is handled in the tests rather than by the dependency: the official generated
// packages are imported by protobuf_test.go, used to marshal real payloads, and the
// results compared against this decoder. Test-only imports are not linked into the
// binary, so correctness is checked against the canonical implementation while the
// shipped artifact stays small.
//
// Protobuf is designed so an unknown field can be skipped safely, which is what makes
// reading a subset sound rather than fragile.

// Wire types, from the protobuf encoding specification.
const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5
)

var errTruncated = errors.New("protobuf: truncated message")

// buf is a cursor over an encoded message.
type buf struct {
	b []byte
	i int
}

func (p *buf) done() bool { return p.i >= len(p.b) }

// tag reads the next field number and wire type.
func (p *buf) tag() (field int, wire int, err error) {
	v, err := p.varint()
	if err != nil {
		return 0, 0, err
	}
	return int(v >> 3), int(v & 0x7), nil
}

func (p *buf) varint() (uint64, error) {
	var v uint64
	var shift uint
	for {
		if p.i >= len(p.b) {
			return 0, errTruncated
		}
		c := p.b[p.i]
		p.i++
		v |= uint64(c&0x7F) << shift
		if c < 0x80 {
			return v, nil
		}
		shift += 7
		if shift > 63 {
			return 0, errors.New("protobuf: varint overflows 64 bits")
		}
	}
}

func (p *buf) fixed64() (uint64, error) {
	if p.i+8 > len(p.b) {
		return 0, errTruncated
	}
	v := binary.LittleEndian.Uint64(p.b[p.i:])
	p.i += 8
	return v, nil
}

func (p *buf) fixed32() (uint32, error) {
	if p.i+4 > len(p.b) {
		return 0, errTruncated
	}
	v := binary.LittleEndian.Uint32(p.b[p.i:])
	p.i += 4
	return v, nil
}

// bytes reads a length-delimited field.
func (p *buf) bytes() ([]byte, error) {
	n, err := p.varint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(p.b)-p.i) {
		return nil, errTruncated
	}
	start := p.i
	p.i += int(n)
	return p.b[start:p.i], nil
}

func (p *buf) string() (string, error) {
	b, err := p.bytes()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// skip advances past a field this decoder does not read. Being able to do this
// safely is what makes decoding a subset of a message sound: a newer producer can add
// fields without breaking an older reader.
func (p *buf) skip(wire int) error {
	switch wire {
	case wireVarint:
		_, err := p.varint()
		return err
	case wireFixed64:
		_, err := p.fixed64()
		return err
	case wireBytes:
		_, err := p.bytes()
		return err
	case wireFixed32:
		_, err := p.fixed32()
		return err
	default:
		return fmt.Errorf("protobuf: unsupported wire type %d", wire)
	}
}

// each walks every field of a message, calling fn for the ones it recognises. A
// handler that returns false means the field was not consumed, so it is skipped.
func each(b []byte, fn func(p *buf, field, wire int) (bool, error)) error {
	p := &buf{b: b}
	for !p.done() {
		field, wire, err := p.tag()
		if err != nil {
			return err
		}
		handled, err := fn(p, field, wire)
		if err != nil {
			return err
		}
		if !handled {
			if err := p.skip(wire); err != nil {
				return err
			}
		}
	}
	return nil
}

// float64frombits converts a fixed64 payload to the double it encodes.
func float64frombits(v uint64) float64 { return math.Float64frombits(v) }
