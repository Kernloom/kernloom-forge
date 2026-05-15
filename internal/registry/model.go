// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package registry loads and exposes the Kernloom core registries.
package registry

// Intent represents an abstract policy goal from the intent registry.
type Intent struct {
	ID                      string   `yaml:"id"`
	Domain                  string   `yaml:"domain"`
	Description             string   `yaml:"description"`
	RiskClass               string   `yaml:"risk_class"`
	DefaultRequiresApproval bool     `yaml:"default_requires_approval"`
	CompilesTo              []string `yaml:"compiles_to"`
}

// Capability represents a technical enforcement or observation ability.
type Capability struct {
	ID                   string   `yaml:"id"`
	Category             string   `yaml:"category"`
	Domain               string   `yaml:"domain"`
	AllowedAdapterTypes  []string `yaml:"allowed_adapter_types"`
	AllowedGranularities []string `yaml:"allowed_granularities"`
	ProducesSignals      []string `yaml:"produces_signals"`
	SupportsTTL          bool     `yaml:"supports_ttl"`
	SupportsDryRun       bool     `yaml:"supports_dry_run"`
	RiskClass            string   `yaml:"risk_class"`
}

// Signal represents a standardised data point.
type Signal struct {
	ID               string    `yaml:"id"`
	Domain           string    `yaml:"domain"`
	Type             string    `yaml:"type"`
	Unit             string    `yaml:"unit"`
	AllowedScopes    []string  `yaml:"allowed_scopes"`
	AllowedProducers []string  `yaml:"allowed_producers"`
	AllowedValues    []string  `yaml:"allowed_values"`
	Aggregation      []string  `yaml:"aggregation"`
	Range            []float64 `yaml:"range"`
}

// Granularity describes the precision level at which a capability can be applied.
type Granularity struct {
	ID string `yaml:"id"`
}

// Scope describes the context to which a signal refers.
type Scope struct {
	ID string `yaml:"id"`
}

// AdapterType defines a class of adapter and its allowed capability prefixes.
type AdapterType struct {
	ID                        string   `yaml:"id"`
	Description               string   `yaml:"description"`
	AllowedCapabilityPrefixes []string `yaml:"allowed_capability_prefixes"`
}

// CompilerRuleTarget is one possible output capability for a compiler rule.
type CompilerRuleTarget struct {
	Capability          string            `yaml:"capability"`
	Domain              string            `yaml:"domain"`
	RequiredGranularity []string          `yaml:"required_granularity"`
	Priority            int               `yaml:"priority"`
	When                map[string]string `yaml:"when"`
}

// CompilerRule maps an intent to one or more capability targets.
type CompilerRule struct {
	ID      string               `yaml:"id"`
	Intent  string               `yaml:"intent"`
	Targets []CompilerRuleTarget `yaml:"targets"`
}

// Registry is the fully loaded and indexed core registry.
type Registry struct {
	Intents       map[string]*Intent
	Capabilities  map[string]*Capability
	Signals       map[string]*Signal
	Granularities map[string]*Granularity
	Scopes        map[string]*Scope
	AdapterTypes  map[string]*AdapterType
	CompilerRules map[string]*CompilerRule
}

// HasIntent returns true if the given ID is a known intent.
func (r *Registry) HasIntent(id string) bool { _, ok := r.Intents[id]; return ok }

// HasCapability returns true if the given ID is a known capability.
func (r *Registry) HasCapability(id string) bool { _, ok := r.Capabilities[id]; return ok }

// HasSignal returns true if the given ID is a known signal.
func (r *Registry) HasSignal(id string) bool { _, ok := r.Signals[id]; return ok }

// HasGranularity returns true if the given ID is a known granularity.
func (r *Registry) HasGranularity(id string) bool { _, ok := r.Granularities[id]; return ok }

// HasScope returns true if the given ID is a known scope.
func (r *Registry) HasScope(id string) bool { _, ok := r.Scopes[id]; return ok }

// HasAdapterType returns true if the given ID is a known adapter type.
func (r *Registry) HasAdapterType(id string) bool { _, ok := r.AdapterTypes[id]; return ok }
