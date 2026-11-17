package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/feysal07/reeve/internal/policy"
	"github.com/feysal07/reeve/internal/resource"
)

// resolveRepository reads the repository an action works in, from .git with no git
// subprocess, and the environment the resource registry's repositories lists put its
// remote in. Only when a rule asks: most policies never do, and every action would
// otherwise pay to read .git.
func resolveRepository(act *policy.Action, resources string) {
	home, _ := os.UserHomeDir()
	wd := act.CWD
	if wd == "" {
		wd, _ = os.Getwd()
	}
	r := resource.ResolveRepository(act.Command, resource.Env{Home: home, WorkDir: wd, Getenv: os.Getenv})
	ctx := &policy.RepositoryContext{State: r.State, Remote: r.Remote, Branch: r.Branch, Detail: r.Detail}
	if r.State == resource.RepoResolved {
		reg, err := loadRegistryStrict(resources, home)
		if err != nil {
			// Found in review: a registry that could not be read left every remote
			// unclassified, so a rule on production matched nothing.
			ctx.State, ctx.Detail = policy.RepositoryUnreadable, err.Error()
		} else {
			ctx.Environment = reg.RepositoryEnvironment(r.Remote)
		}
	}
	act.Repository = ctx
}

// loadRegistryStrict is loadRegistry that says when a registry named, or found, could not
// be read, rather than passing it over as absent.
func loadRegistryStrict(explicit, home string) (*resource.Registry, error) {
	paths := []string{explicit}
	if explicit == "" {
		paths = resource.DefaultPaths(runtime.GOOS, os.Getenv("ProgramData"), home)
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Lstat(p); os.IsNotExist(err) && explicit == "" {
			continue
		}
		r, err := resource.Load(p)
		if err != nil {
			return nil, fmt.Errorf("the resource registry %s cannot be read: %w", p, err)
		}
		return r, nil
	}
	return nil, nil
}
