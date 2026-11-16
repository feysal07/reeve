//go:build windows

package audit

import "os"

// openNonBlocking is a plain open on Windows, where a named pipe is not a file in the
// log's directory and opening a file there does not block.
func openNonBlocking(path string) (*os.File, error) {
	return os.Open(path)
}
