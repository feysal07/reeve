package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/feysal07/reeve/internal/compile"
	"github.com/feysal07/reeve/internal/model"
	"github.com/feysal07/reeve/internal/policy"
)

// runPolicyCompile turns one policy into each agent's own configuration.
//
// The output that matters most is not the files: it is the coverage report. Native
// configuration cannot express everything a policy can say, and an operator who does
// not know which rules survived will believe they are protected by files that do not
// protect them.
func runPolicyCompile(args []string) error {
	fs := flag.NewFlagSet("policy compile", flag.ContinueOnError)
	agentFlag := fs.String("agent", "", "compile for one agent only")
	platform := fs.String("platform", runtime.GOOS, "target platform for file paths: linux, darwin or windows")
	out := fs.String("out", "", "write artifacts to this directory instead of describing them")
	quiet := fs.Bool("quiet", false, "suppress the coverage report")
	strict := fs.Bool("strict", false, "exit non-zero if any rule is not fully enforced natively")
	file, flags := splitFileAndFlags(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if file == "" {
		return fmt.Errorf("usage: reeve policy compile <file> [flags]")
	}

	p, err := policy.Load(file)
	if err != nil {
		return err
	}

	compilers := compile.All()
	if *agentFlag != "" {
		c, err := compile.For(model.AgentID(*agentFlag))
		if err != nil {
			return err
		}
		compilers = []compile.Compiler{c}
	}

	if p.Settings == nil {
		fmt.Fprintln(os.Stderr,
			"warning: this policy has no settings block, so the compiled files carry rules but no posture:\n"+
				"         no bypass lock, no telemetry destination, no MCP allow list and no guard registration.")
	}

	var anyGap bool
	for _, c := range compilers {
		res, err := c.Compile(p, *platform)
		if err != nil {
			return fmt.Errorf("%s: %w", c.DisplayName(), err)
		}

		fmt.Printf("\n%s\n%s\n", c.DisplayName(), strings.Repeat("=", len(c.DisplayName())))

		for _, a := range res.Artifacts {
			if *out != "" {
				dest := filepath.Join(*out, a.Filename)
				if err := os.MkdirAll(*out, 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(dest, a.Content, 0o644); err != nil {
					return err
				}
				fmt.Printf("\n  wrote %s\n", dest)
			} else {
				fmt.Printf("\n  %s\n", a.Path)
			}
			fmt.Printf("  %s\n", wrap(a.Describe, 74, "  "))
			if *out == "" {
				fmt.Println()
				for _, line := range strings.Split(strings.TrimRight(string(a.Content), "\n"), "\n") {
					fmt.Printf("    %s\n", line)
				}
			}
		}

		if !*quiet {
			printCoverage(res)
		}

		for _, w := range res.Warnings {
			fmt.Printf("\n  warning: %s\n", wrap(w, 74, "           "))
		}

		s := compile.Summarise(res.Coverage)
		if s.Partial > 0 || s.GuardOnly > 0 || s.Unenforceable > 0 {
			anyGap = true
		}
	}

	fmt.Println()
	if *strict && anyGap {
		fmt.Fprintln(os.Stderr,
			"strict: some rules are not fully enforced by native configuration alone.")
		os.Exit(2)
	}
	return nil
}

func printCoverage(res compile.Result) {
	if len(res.Coverage) == 0 {
		return
	}
	s := compile.Summarise(res.Coverage)

	fmt.Printf("\n  Coverage: %d enforced natively, %d partially, %d by the guard only",
		s.Native, s.Partial, s.GuardOnly)
	// Printed on the same line, and only when it is not zero, so a number that
	// should almost always be zero is conspicuous on the rare occasion it is not.
	if s.Unenforceable > 0 {
		fmt.Printf(", %d NOT ENFORCED ANYWHERE", s.Unenforceable)
	}
	fmt.Print("\n\n")

	for _, c := range res.Coverage {
		fmt.Printf("    %-12s %-26s %s\n", c.Status, c.RuleID, c.Decision)
		for _, e := range c.Emitted {
			fmt.Printf("      + %s\n", e)
		}
		if c.Reason != "" {
			fmt.Printf("      %s\n", wrap(c.Reason, 68, "      "))
		}
	}

	if s.GuardOnly > 0 || s.Partial > 0 {
		fmt.Printf("\n  %s\n",
			wrap("Rules above marked partial or guard-only are not enforced by these files. "+
				"They hold only while the guard is running, so deploy the guard alongside "+
				"this configuration rather than instead of it.", 74, "  "))
	}
	// Separate from the sentence above, and phrased as an instruction rather than
	// a caveat, because "deploy the guard as well" is not the remedy here and
	// following it would leave the operator believing they had closed the gap.
	if s.Unenforceable > 0 {
		fmt.Printf("\n  %s\n",
			wrap("Rules marked unenforceable are covered by neither this configuration "+
				"nor the guard. Deploying the guard will not close them. Read the reason "+
				"on each one and either accept the gap deliberately or drop the rule for "+
				"this agent, because as written it will never fire and nothing will say "+
				"so again.", 74, "  "))
	}
}
