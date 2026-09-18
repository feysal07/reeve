package telemetry

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/feysal07/reeve/internal/config"
)

// Price is what one model costs, in US dollars per million tokens.
type Price struct {
	Input         float64 `yaml:"input"`
	Output        float64 `yaml:"output"`
	CacheRead     float64 `yaml:"cacheRead"`
	CacheCreation float64 `yaml:"cacheCreation"`
}

// PriceTable maps a model name to its price.
//
// Cost is computed here rather than taken from the agents for three reasons. Two of
// the three supported agents report no cost at all, so there would be nothing to take.
// The one that does reports an estimate at list price, which is wrong for any
// organisation with negotiated rates. And a number that means different things
// depending on which agent produced it cannot be summed, which is the entire point of
// a cost report.
type PriceTable struct {
	// Currency is recorded for the report's benefit; all arithmetic is in it.
	Currency string `yaml:"currency"`
	// Models is keyed by a name or prefix. The longest matching prefix wins, so a
	// table can price a family and then override one member of it.
	Models map[string]Price `yaml:"models"`
	// Multiplier scales every computed cost, for an organisation that recharges at
	// something other than the rate it pays.
	Multiplier float64 `yaml:"multiplier"`
}

// DefaultPrices is a starting table at published list rates.
//
// It is deliberately incomplete and will go out of date. Any organisation that cares
// about the number should supply its own with --prices, which is why an unpriced model
// is reported rather than silently costed at zero.
var DefaultPrices = PriceTable{
	Currency:   "USD",
	Multiplier: 1,
	Models: map[string]Price{
		"claude-opus":   {Input: 15, Output: 75, CacheRead: 1.50, CacheCreation: 18.75},
		"claude-sonnet": {Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75},
		"claude-haiku":  {Input: 0.80, Output: 4, CacheRead: 0.08, CacheCreation: 1},
		"gpt-5":         {Input: 1.25, Output: 10, CacheRead: 0.125},
		"gpt-4":         {Input: 2.50, Output: 10, CacheRead: 0.25},
		"o3":            {Input: 2, Output: 8, CacheRead: 0.50},
		"gemini-2.5":    {Input: 1.25, Output: 10, CacheRead: 0.31},
		"gemini-3":      {Input: 2, Output: 12, CacheRead: 0.50},
	},
}

// LoadPrices reads a price table from a YAML file.
func LoadPrices(path string) (PriceTable, error) {
	b, err := config.ReadFile(path)
	if err != nil {
		return PriceTable{}, err
	}
	var t PriceTable
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
		return PriceTable{}, fmt.Errorf("parse price table: %w", err)
	}
	if t.Multiplier == 0 {
		t.Multiplier = 1
	}
	if t.Currency == "" {
		t.Currency = "USD"
	}
	return t, nil
}

// Cost computes what a request cost, and reports whether the model was priced at all.
//
// An unknown model returns priced=false rather than zero. Zero is indistinguishable
// from free, and a cost report that quietly treats an unpriced model as costing
// nothing is worse than one that admits it does not know.
func (t PriceTable) Cost(model string, tok Tokens) (usd float64, priced bool) {
	p, ok := t.lookup(model)
	if !ok {
		return 0, false
	}
	const perMillion = 1_000_000.0
	usd = float64(tok.Input)/perMillion*p.Input +
		float64(tok.Output)/perMillion*p.Output +
		float64(tok.CacheRead)/perMillion*p.CacheRead +
		float64(tok.CacheCreation)/perMillion*p.CacheCreation

	m := t.Multiplier
	if m == 0 {
		m = 1
	}
	return usd * m, true
}

// lookup finds the most specific entry matching a model name. Model names carry
// dates and revisions that change often, so matching on the longest prefix keeps a
// table useful without an edit every time a vendor ships a point release.
func (t PriceTable) lookup(model string) (Price, bool) {
	if model == "" {
		return Price{}, false
	}
	name := strings.ToLower(model)

	if p, ok := t.Models[name]; ok {
		return p, true
	}

	var best string
	for k := range t.Models {
		lk := strings.ToLower(k)
		if strings.HasPrefix(name, lk) && len(lk) > len(best) {
			best = lk
		}
	}
	if best == "" {
		return Price{}, false
	}
	for k, v := range t.Models {
		if strings.EqualFold(k, best) {
			return v, true
		}
	}
	return Price{}, false
}
