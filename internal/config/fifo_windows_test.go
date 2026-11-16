//go:build windows

package config

import "errors"

func mkfifo(string) error { return errors.New("no FIFOs on Windows") }
