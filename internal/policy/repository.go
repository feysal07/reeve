package policy

import "fmt"

// The states of the repository an action works in, as the guard read it.
const (
	RepositoryResolved   = "resolved"
	RepositoryNone       = "none"
	RepositoryUnknown    = "unknown"
	RepositoryUnreadable = "unreadable"
)

// RepositoryContext is the repository an action works in, resolved by the guard before
// Evaluate: which remote it reaches, which environment the resource registry puts that
// remote in, and which branch a push lands on, or the branch checked out.
type RepositoryContext struct {
	State       string
	Remote      string
	Branch      string
	Environment string
	// Detail says why the state is unknown or unreadable, naming files, never a URL.
	Detail string
}

// RepositoryMatch matches the repository an action works in: its environment, from the
// resource registry's repositories lists, and the branch, as globs.
//
// Until v0.7.0 a rule could not say "ask before pushing to main of a production
// repository": the guard knew neither. Kept apart from Match.Environment, which is the
// environment a command reaches, so a production rule on infrastructure does not start
// asking on every ls in a repository the registry calls production.
type RepositoryMatch struct {
	Environment []string `yaml:"environment,omitempty"`
	Branch      []string `yaml:"branch,omitempty"`
}

func (m *RepositoryMatch) validate(rule string) error {
	if len(m.Environment) == 0 && len(m.Branch) == 0 {
		return fmt.Errorf("rule %s: repository names no environment and no branch, so it would match every repository", rule)
	}
	return nil
}

func (m *RepositoryMatch) matches(a Action) bool {
	r := a.Repository
	if r == nil || r.State == RepositoryNone || r.State == RepositoryUnreadable {
		return false
	}
	env, branch := r.Environment, r.Branch
	if r.State == RepositoryUnknown {
		env, branch = "unknown", ""
	}
	if len(m.Environment) > 0 && !anyEqualFold(m.Environment, env) {
		return false
	}
	if len(m.Branch) > 0 && !anyGlob(m.Branch, branch) {
		return false
	}
	return true
}

// unresolved reports that the repository could not be read, or was never resolved: a
// rule on it refuses rather than reading that as no repository.
//
// Unknown too, unless the rule names unknown. Found in review: an action the reader
// could not place matched nothing, so "cd . && git push origin main" walked past a rule
// on production main. Unknown is an input the rule depends on and could not read.
func (m *RepositoryMatch) unresolved(a Action) bool {
	r := a.Repository
	if r == nil || r.State == RepositoryUnreadable {
		return true
	}
	return r.State == RepositoryUnknown && !anyEqualFold(m.Environment, "unknown")
}

// NeedsRepository reports whether any rule matches on the repository, so the guard reads
// .git only for policies that asked.
func (p *Policy) NeedsRepository() bool {
	for _, r := range p.Rules {
		if r.Match.Repository != nil {
			return true
		}
	}
	return false
}
