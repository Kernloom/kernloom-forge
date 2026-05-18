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
// ParameterSpec declares a single allowed parameter for a capability.
type ParameterSpec struct {
	// Type is the expected value type: "uint", "string", "float", "bool".
	Type string `yaml:"type"`
	// Description explains what the parameter controls and its effect on enforcement mode.
	Description string `yaml:"description"`
	// Optional: when true the parameter may be absent. When false it is required.
	Optional bool `yaml:"optional"`
}

type Capability struct {
	ID                   string   `yaml:"id"`
	Category             string   `yaml:"category"`
	Domain               string   `yaml:"domain"`
	AllowedRoles         []string `yaml:"allowed_roles"`
	AllowedGranularities []string `yaml:"allowed_granularities"`
	ProducesSignals      []string `yaml:"produces_signals"`
	SupportsTTL          bool     `yaml:"supports_ttl"`
	SupportsDryRun       bool     `yaml:"supports_dry_run"`
	RiskClass            string   `yaml:"risk_class"`
	// AllowedParameters declares which then.params keys are valid for this capability
	// and their expected types. Absent = no parameters allowed.
	AllowedParameters map[string]ParameterSpec `yaml:"allowed_parameters,omitempty"`
}

// Signal represents a standardised data point.
type Signal struct {
	ID               string    `yaml:"id"`
	Domain           string    `yaml:"domain"`
	Type             string    `yaml:"type"`
	Unit             string    `yaml:"unit"`
	AllowedScopes    []string  `yaml:"allowed_scopes"`
	AllowedProducers []string  `yaml:"allowed_producers"` // references ComponentRole IDs
	AllowedValues    []string  `yaml:"allowed_values"`
	Aggregation      []string  `yaml:"aggregation"`
	Range            []float64 `yaml:"range"`
}

// Granularity describes the precision level at which a capability can be applied or observed.
type Granularity struct {
	ID    string `yaml:"id"`
	Group string `yaml:"group"`
}

// Scope describes the context to which a signal refers (aggregation / learning dimension).
type Scope struct {
	ID string `yaml:"id"`
}

// ComponentRole defines a pure functional role of a component in the policy system.
// Roles describe WHAT a component does, not HOW it is implemented.
type ComponentRole struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
}

// ComponentProfile is a technical template that describes where and how a component
// operates. Profiles describe HOW the component works technically.
// Distinct from ComponentRole (what it does) and NodeDefinition (concrete instance).
type ComponentProfile struct {
	ID                        string         `yaml:"id"`
	Description               string         `yaml:"description"`
	TypicalRoles              []string       `yaml:"typical_roles"`
	Layers                    []string       `yaml:"layers"`
	AllowedCapabilityPrefixes []string       `yaml:"allowed_capability_prefixes"`
	DefaultConstraints        map[string]any `yaml:"default_constraints"`
}

// BaselineStatistic is a standardised output field produced by an analyzer.
// Forge standardises the name; components decide the computation internally.
type BaselineStatistic struct {
	ID            string    `yaml:"id"`
	Description   string    `yaml:"description"`
	ValueType     string    `yaml:"value_type"`
	Unit          string    `yaml:"unit"`
	AllowedValues []string  `yaml:"allowed_values"`
	Range         []float64 `yaml:"range"`
}

// SelectionTraitDefinition defines a single compiler-scoring dimension and its
// allowed enumeration values.
type SelectionTraitDefinition struct {
	ID            string   `yaml:"id"`
	Description   string   `yaml:"description"`
	AllowedValues []string `yaml:"allowed_values"`
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
	Intents            map[string]*Intent
	Capabilities       map[string]*Capability
	Signals            map[string]*Signal
	Granularities      map[string]*Granularity
	Scopes             map[string]*Scope
	ComponentRoles     map[string]*ComponentRole
	ComponentProfiles  map[string]*ComponentProfile
	CompilerRules      map[string]*CompilerRule
	BaselineStatistics map[string]*BaselineStatistic
	SelectionTraits    map[string]*SelectionTraitDefinition
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

// HasComponentRole returns true if the given ID is a known component role.
func (r *Registry) HasComponentRole(id string) bool { _, ok := r.ComponentRoles[id]; return ok }

// HasComponentProfile returns true if the given ID is a known component profile.
func (r *Registry) HasComponentProfile(id string) bool { _, ok := r.ComponentProfiles[id]; return ok }

// HasBaselineStatistic returns true if the given ID is a known baseline statistic.
func (r *Registry) HasBaselineStatistic(id string) bool {
	_, ok := r.BaselineStatistics[id]
	return ok
}

// HasSelectionTrait returns true if the given ID is a known selection trait.
func (r *Registry) HasSelectionTrait(id string) bool { _, ok := r.SelectionTraits[id]; return ok }
