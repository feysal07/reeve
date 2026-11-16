//go:build windows

package audit

import "errors"

func mkfifo(string) error { return errors.New("no FIFOs on Windows") }
