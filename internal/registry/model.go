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

// ActionConstraint defines a valid constraint key for effects[].constraints
// and PolicyAssignment.delegation.action_bounds.
type ActionConstraint struct {
	ID          string    `yaml:"id"`
	ValueType   string    `yaml:"value_type"` // duration|ratio|integer|boolean|string_list
	Description string    `yaml:"description"`
	AppliesTo   []string  `yaml:"applies_to"` // effect types this constraint is valid for
	Range       []float64 `yaml:"range,omitempty"`
	Example     any       `yaml:"example,omitempty"`
}

// TrustAssuranceLevel defines an ordered trust level in the assurance scale.
type TrustAssuranceLevel struct {
	ID          string `yaml:"id"`
	Level       int    `yaml:"level"` // numeric order; higher = more trusted
	Description string `yaml:"description"`
	Default     bool   `yaml:"default,omitempty"`
}

// DecisionMode defines how a local PDP interacts with the central authority.
type DecisionMode struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Default     bool   `yaml:"default,omitempty"`
}

// FailoverBehavior defines what a local PDP does when Forge is unreachable.
type FailoverBehavior struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Risk        string `yaml:"risk,omitempty"` // low|medium|high
	Default     bool   `yaml:"default,omitempty"`
}

// EffectType represents a canonical policy effect type.
type EffectType struct {
	ID              string   `yaml:"id"`
	Description     string   `yaml:"description"`
	AllowedContexts []string `yaml:"allowed_contexts"`
	RequiredFields  []string `yaml:"required_fields"`
}

// PolicyContext defines what is available during policy evaluation for a given context.
type PolicyContext struct {
	ID               string   `yaml:"id"`
	Description      string   `yaml:"description"`
	AvailableObjects []string `yaml:"available_objects"`
	AllowedEffects   []string `yaml:"allowed_effects"`
	BindingSources   []string `yaml:"binding_sources"`
}

// Registry is the fully loaded and indexed core registry.
type Registry struct {
	Intents              map[string]*Intent
	Capabilities         map[string]*Capability
	Signals              map[string]*Signal
	Granularities        map[string]*Granularity
	Scopes               map[string]*Scope
	ComponentRoles       map[string]*ComponentRole
	ComponentProfiles    map[string]*ComponentProfile
	CompilerRules        map[string]*CompilerRule
	BaselineStatistics   map[string]*BaselineStatistic
	SelectionTraits      map[string]*SelectionTraitDefinition
	EffectTypes          map[string]*EffectType
	PolicyContexts       map[string]*PolicyContext
	ActionConstraints    map[string]*ActionConstraint
	TrustAssuranceLevels map[string]*TrustAssuranceLevel
	DecisionModes        map[string]*DecisionMode
	FailoverBehaviors    map[string]*FailoverBehavior
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

// HasEffectType returns true if the given ID is a known effect type.
func (r *Registry) HasEffectType(id string) bool { _, ok := r.EffectTypes[id]; return ok }

// HasPolicyContext returns true if the given ID is a known policy context.
func (r *Registry) HasPolicyContext(id string) bool { _, ok := r.PolicyContexts[id]; return ok }

// HasActionConstraint returns true if the given ID is a known action constraint.
func (r *Registry) HasActionConstraint(id string) bool { _, ok := r.ActionConstraints[id]; return ok }

// HasTrustAssuranceLevel returns true if the given ID is a known trust assurance level.
func (r *Registry) HasTrustAssuranceLevel(id string) bool {
	_, ok := r.TrustAssuranceLevels[id]
	return ok
}

// HasDecisionMode returns true if the given ID is a known decision mode.
func (r *Registry) HasDecisionMode(id string) bool { _, ok := r.DecisionModes[id]; return ok }

// HasFailoverBehavior returns true if the given ID is a known failover behavior.
func (r *Registry) HasFailoverBehavior(id string) bool { _, ok := r.FailoverBehaviors[id]; return ok }

// ConstraintValidForEffect returns true when the given constraint key is declared
// as applying to the given effect type. Returns true for unknown registries (graceful).
func (r *Registry) ConstraintValidForEffect(constraintID, effectType string) bool {
	c, ok := r.ActionConstraints[constraintID]
	if !ok {
		return false // unknown constraint
	}
	for _, t := range c.AppliesTo {
		if t == effectType {
			return true
		}
	}
	return false
}

// EffectAllowedForContext returns true when effectID is listed in the context's allowed_effects.
func (r *Registry) EffectAllowedForContext(contextID, effectID string) bool {
	ctx, ok := r.PolicyContexts[contextID]
	if !ok {
		return false
	}
	for _, e := range ctx.AllowedEffects {
		if e == effectID {
			return true
		}
	}
	return false
}
