// Package config reads configuration files the way they actually appear on disk.
package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// utf8BOM is the byte order mark Windows editors and PowerShell prepend to a file
// written as UTF-8.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// StripBOM removes a leading UTF-8 byte order mark.
//
// This matters more than it looks. PowerShell's Set-Content -Encoding utf8 writes a
// BOM, as do several Windows editors, so administrator-authored configuration
// routinely has one. Go's JSON, YAML and TOML parsers all reject it. Without this, a
// managed settings file written on Windows parses as nothing, and every rule in it is
// silently absent while the file sits there looking deployed. Reeve would then report
// no findings against a machine it had actually failed to read.
func StripBOM(b []byte) []byte {
	return bytes.TrimPrefix(b, utf8BOM)
}

// ReadFile reads a configuration file and removes any byte order mark.
func ReadFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return StripBOM(b), nil
}

// maxRegular is the most ReadRegularFile reads. Configuration files are kilobytes; a
// file larger than this in a directory somebody else controls is not one.
const maxRegular = 4 << 20

// ReadRegularFile reads a configuration file only if it is a regular file, opening it
// without blocking and refusing one larger than maxRegular.
func ReadRegularFile(path string) ([]byte, error) {
	f, err := openNonBlocking(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maxRegular {
		return nil, fmt.Errorf("%s is %d bytes, larger than any configuration file", path, info.Size())
	}
	b, err := io.ReadAll(io.LimitReader(f, maxRegular+1))
	if err != nil {
		return nil, err
	}
	return StripBOM(b), nil
}
