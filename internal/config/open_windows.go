//go:build windows

package config

import "os"

// openNonBlocking is a plain open on Windows, where a named pipe is not a file in a
// project directory and opening a file there does not block.
func openNonBlocking(path string) (*os.File, error) {
	return os.Open(path)
}
