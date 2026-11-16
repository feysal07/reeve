//go:build !windows

package config

import (
	"os"
	"syscall"
)

// openNonBlocking opens without waiting: a FIFO with no writer would otherwise block the
// open itself, before there is a file to ask whether it is regular.
func openNonBlocking(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
