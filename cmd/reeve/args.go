package main

import "strings"

// splitFileAndFlags separates the first positional argument from the flags.
//
// Go's flag package stops parsing at the first non-flag argument, so
// "policy compile file.yaml --strict" would silently treat --strict as a positional
// argument and ignore it. A flag that is accepted and then ignored is worse than one
// that errors, because the operator believes it took effect. Extracting the filename
// first lets flags appear on either side of it, which is what people type.
func splitFileAndFlags(args []string) (file string, flags []string) {
	// Flags that take a separate value, so the value is not mistaken for the file.
	valueFlags := map[string]bool{
		"--agent": true, "--platform": true, "--out": true, "--policy": true,
		"--log": true, "--dir": true, "--fail-on": true, "--kind": true,
		"--tool": true, "--command": true, "--path": true, "--url": true,
		"--mcp-server": true, "--mcp-tool": true,
	}

	skipNext := false
	for _, a := range args {
		if skipNext {
			flags = append(flags, a)
			skipNext = false
			continue
		}
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			// --flag=value carries its own value; --flag value does not.
			if valueFlags[a] && !strings.Contains(a, "=") {
				skipNext = true
			}
			continue
		}
		if file == "" {
			file = a
			continue
		}
		flags = append(flags, a)
	}
	return file, flags
}
