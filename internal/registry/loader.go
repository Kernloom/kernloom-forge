// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// raw envelope types for YAML unmarshalling.

type rawIntents struct {
	Intents []Intent `yaml:"intents"`
}

type rawCapabilities struct {
	Capabilities []Capability `yaml:"capabilities"`
}

type rawSignals struct {
	Signals []Signal `yaml:"signals"`
}

type rawGranularities struct {
	Granularities []Granularity `yaml:"granularities"`
}

type rawScopes struct {
	Scopes []Scope `yaml:"scopes"`
}

type rawComponentRoles struct {
	ComponentRoles []ComponentRole `yaml:"component_roles"`
}

type rawComponentProfiles struct {
	ComponentProfiles []ComponentProfile `yaml:"component_profiles"`
}

type rawBaselineStatistics struct {
	BaselineStatistics []BaselineStatistic `yaml:"baseline_statistics"`
}

type rawSelectionTraits struct {
	SelectionTraits []SelectionTraitDefinition `yaml:"selection_traits"`
}

type rawCompilerRules struct {
	CompilerRules []CompilerRule `yaml:"compiler_rules"`
}

// LoadDir loads all registry files from dir and returns a validated Registry.
func LoadDir(dir string) (*Registry, error) {
	r := &Registry{
		Intents:              make(map[string]*Intent),
		Capabilities:         make(map[string]*Capability),
		Signals:              make(map[string]*Signal),
		Granularities:        make(map[string]*Granularity),
		Scopes:               make(map[string]*Scope),
		ComponentRoles:       make(map[string]*ComponentRole),
		ComponentProfiles:    make(map[string]*ComponentProfile),
		CompilerRules:        make(map[string]*CompilerRule),
		BaselineStatistics:   make(map[string]*BaselineStatistic),
		SelectionTraits:      make(map[string]*SelectionTraitDefinition),
		EffectTypes:          make(map[string]*EffectType),
		PolicyContexts:       make(map[string]*PolicyContext),
		ActionConstraints:    make(map[string]*ActionConstraint),
		TrustAssuranceLevels: make(map[string]*TrustAssuranceLevel),
		DecisionModes:        make(map[string]*DecisionMode),
		FailoverBehaviors:    make(map[string]*FailoverBehavior),
		Metrics:              make(map[string]*MetricEntry),
		LabelPolicies:        make(map[string]*LabelPolicyEntry),
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read registry dir %s: %w", dir, err)
	}

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, f.Name())
		if err := r.loadFile(path); err != nil {
			return nil, fmt.Errorf("load %s: %w", f.Name(), err)
		}
	}

	return r, r.validate()
}

func (r *Registry) loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	base := filepath.Base(path)
	switch base {
	case "intents.yaml":
		var v rawIntents
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.Intents {
			item := &v.Intents[i]
			if item.ID == "" {
				return fmt.Errorf("intent missing id")
			}
			if _, dup := r.Intents[item.ID]; dup {
				return fmt.Errorf("duplicate intent id: %s", item.ID)
			}
			r.Intents[item.ID] = item
		}

	case "capabilities.yaml":
		var v rawCapabilities
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.Capabilities {
			item := &v.Capabilities[i]
			if item.ID == "" {
				return fmt.Errorf("capability missing id")
			}
			if _, dup := r.Capabilities[item.ID]; dup {
				return fmt.Errorf("duplicate capability id: %s", item.ID)
			}
			r.Capabilities[item.ID] = item
		}

	case "signals.yaml":
		var v rawSignals
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.Signals {
			item := &v.Signals[i]
			if item.ID == "" {
				return fmt.Errorf("signal missing id")
			}
			if _, dup := r.Signals[item.ID]; dup {
				return fmt.Errorf("duplicate signal id: %s", item.ID)
			}
			r.Signals[item.ID] = item
		}

	case "granularities.yaml":
		var v rawGranularities
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.Granularities {
			item := &v.Granularities[i]
			if item.ID == "" {
				return fmt.Errorf("granularity missing id")
			}
			if _, dup := r.Granularities[item.ID]; dup {
				return fmt.Errorf("duplicate granularity id: %s", item.ID)
			}
			r.Granularities[item.ID] = item
		}

	case "scopes.yaml":
		var v rawScopes
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.Scopes {
			item := &v.Scopes[i]
			if item.ID == "" {
				return fmt.Errorf("scope missing id")
			}
			if _, dup := r.Scopes[item.ID]; dup {
				return fmt.Errorf("duplicate scope id: %s", item.ID)
			}
			r.Scopes[item.ID] = item
		}

	case "component_roles.yaml":
		var v rawComponentRoles
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.ComponentRoles {
			item := &v.ComponentRoles[i]
			if item.ID == "" {
				return fmt.Errorf("component_role missing id")
			}
			if _, dup := r.ComponentRoles[item.ID]; dup {
				return fmt.Errorf("duplicate component_role id: %s", item.ID)
			}
			r.ComponentRoles[item.ID] = item
		}

	case "component_profiles.yaml":
		var v rawComponentProfiles
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.ComponentProfiles {
			item := &v.ComponentProfiles[i]
			if item.ID == "" {
				return fmt.Errorf("component_profile missing id")
			}
			if _, dup := r.ComponentProfiles[item.ID]; dup {
				return fmt.Errorf("duplicate component_profile id: %s", item.ID)
			}
			r.ComponentProfiles[item.ID] = item
		}

	case "baseline_statistics.yaml":
		var v rawBaselineStatistics
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.BaselineStatistics {
			item := &v.BaselineStatistics[i]
			if item.ID == "" {
				return fmt.Errorf("baseline_statistic missing id")
			}
			if _, dup := r.BaselineStatistics[item.ID]; dup {
				return fmt.Errorf("duplicate baseline_statistic id: %s", item.ID)
			}
			r.BaselineStatistics[item.ID] = item
		}

	case "selection_traits.yaml":
		var v rawSelectionTraits
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.SelectionTraits {
			item := &v.SelectionTraits[i]
			if item.ID == "" {
				return fmt.Errorf("selection_trait missing id")
			}
			if _, dup := r.SelectionTraits[item.ID]; dup {
				return fmt.Errorf("duplicate selection_trait id: %s", item.ID)
			}
			r.SelectionTraits[item.ID] = item
		}

	case "compiler_rules.yaml":
		var v rawCompilerRules
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.CompilerRules {
			item := &v.CompilerRules[i]
			if item.ID == "" {
				return fmt.Errorf("compiler_rule missing id")
			}
			if _, dup := r.CompilerRules[item.ID]; dup {
				return fmt.Errorf("duplicate compiler_rule id: %s", item.ID)
			}
			r.CompilerRules[item.ID] = item
		}

	case "effect_types.yaml":
		var v struct {
			EffectTypes []EffectType `yaml:"effect_types"`
		}
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.EffectTypes {
			item := &v.EffectTypes[i]
			if item.ID == "" {
				return fmt.Errorf("effect_type missing id")
			}
			if _, dup := r.EffectTypes[item.ID]; dup {
				return fmt.Errorf("duplicate effect_type id: %s", item.ID)
			}
			r.EffectTypes[item.ID] = item
		}

	case "policy_contexts.yaml":
		var v struct {
			PolicyContexts []PolicyContext `yaml:"policy_contexts"`
		}
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.PolicyContexts {
			item := &v.PolicyContexts[i]
			if item.ID == "" {
				return fmt.Errorf("policy_context missing id")
			}
			if _, dup := r.PolicyContexts[item.ID]; dup {
				return fmt.Errorf("duplicate policy_context id: %s", item.ID)
			}
			r.PolicyContexts[item.ID] = item
		}

	case "action_constraints.yaml":
		var v struct {
			ActionConstraints []ActionConstraint `yaml:"action_constraints"`
		}
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.ActionConstraints {
			item := &v.ActionConstraints[i]
			if item.ID == "" {
				return fmt.Errorf("action_constraint missing id")
			}
			if _, dup := r.ActionConstraints[item.ID]; dup {
				return fmt.Errorf("duplicate action_constraint id: %s", item.ID)
			}
			r.ActionConstraints[item.ID] = item
		}

	case "trust_assurance_levels.yaml":
		var v struct {
			TrustAssuranceLevels []TrustAssuranceLevel `yaml:"trust_assurance_levels"`
		}
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.TrustAssuranceLevels {
			item := &v.TrustAssuranceLevels[i]
			if item.ID == "" {
				return fmt.Errorf("trust_assurance_level missing id")
			}
			if _, dup := r.TrustAssuranceLevels[item.ID]; dup {
				return fmt.Errorf("duplicate trust_assurance_level id: %s", item.ID)
			}
			r.TrustAssuranceLevels[item.ID] = item
		}

	case "decision_modes.yaml":
		var v struct {
			DecisionModes []DecisionMode `yaml:"decision_modes"`
		}
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.DecisionModes {
			item := &v.DecisionModes[i]
			if item.ID == "" {
				return fmt.Errorf("decision_mode missing id")
			}
			if _, dup := r.DecisionModes[item.ID]; dup {
				return fmt.Errorf("duplicate decision_mode id: %s", item.ID)
			}
			r.DecisionModes[item.ID] = item
		}

	case "failover_behaviors.yaml":
		var v struct {
			FailoverBehaviors []FailoverBehavior `yaml:"failover_behaviors"`
		}
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.FailoverBehaviors {
			item := &v.FailoverBehaviors[i]
			if item.ID == "" {
				return fmt.Errorf("failover_behavior missing id")
			}
			if _, dup := r.FailoverBehaviors[item.ID]; dup {
				return fmt.Errorf("duplicate failover_behavior id: %s", item.ID)
			}
			r.FailoverBehaviors[item.ID] = item
		}

	case "metrics.yaml":
		var v struct {
			Metrics []MetricEntry `yaml:"metrics"`
		}
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.Metrics {
			item := &v.Metrics[i]
			if item.ID == "" {
				return fmt.Errorf("metric missing id")
			}
			if _, dup := r.Metrics[item.ID]; dup {
				return fmt.Errorf("duplicate metric id: %s", item.ID)
			}
			r.Metrics[item.ID] = item
		}

	case "label_policies.yaml":
		var v struct {
			LabelPolicies []LabelPolicyEntry `yaml:"label_policies"`
		}
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.LabelPolicies {
			item := &v.LabelPolicies[i]
			if item.ID == "" {
				return fmt.Errorf("label_policy missing id")
			}
			if _, dup := r.LabelPolicies[item.ID]; dup {
				return fmt.Errorf("duplicate label_policy id: %s", item.ID)
			}
			r.LabelPolicies[item.ID] = item
		}
	}
	return nil
}

// validate performs cross-reference checks after all files are loaded.
func (r *Registry) validate() error {
	// Every capability referenced by an intent's compiles_to must exist.
	for _, intent := range r.Intents {
		for _, capID := range intent.CompilesTo {
			if !r.HasCapability(capID) {
				return fmt.Errorf("intent %s: compiles_to references unknown capability %q", intent.ID, capID)
			}
		}
	}

	// Every capability's allowed_roles must be known component roles.
	for _, cap := range r.Capabilities {
		for _, role := range cap.AllowedRoles {
			if !r.HasComponentRole(role) {
				return fmt.Errorf("capability %s: unknown component_role %q", cap.ID, role)
			}
		}
		for _, g := range cap.AllowedGranularities {
			if !r.HasGranularity(g) {
				return fmt.Errorf("capability %s: unknown granularity %q", cap.ID, g)
			}
		}
		for _, sig := range cap.ProducesSignals {
			if !r.HasSignal(sig) {
				return fmt.Errorf("capability %s: produces unknown signal %q", cap.ID, sig)
			}
		}
	}

	// Every signal's allowed_scopes must be known; allowed_producers must be known roles.
	for _, sig := range r.Signals {
		for _, sc := range sig.AllowedScopes {
			if !r.HasScope(sc) {
				return fmt.Errorf("signal %s: unknown scope %q", sig.ID, sc)
			}
		}
		for _, role := range sig.AllowedProducers {
			if !r.HasComponentRole(role) {
				return fmt.Errorf("signal %s: unknown producer component_role %q", sig.ID, role)
			}
		}
	}

	// Every component profile's typical_roles must be known.
	for _, profile := range r.ComponentProfiles {
		for _, role := range profile.TypicalRoles {
			if !r.HasComponentRole(role) {
				return fmt.Errorf("component_profile %s: unknown role %q", profile.ID, role)
			}
		}
	}

	// Every compiler rule must reference a known intent and known capabilities/granularities.
	for _, rule := range r.CompilerRules {
		if !r.HasIntent(rule.Intent) {
			return fmt.Errorf("compiler_rule %s: unknown intent %q", rule.ID, rule.Intent)
		}
		for _, t := range rule.Targets {
			if !r.HasCapability(t.Capability) {
				return fmt.Errorf("compiler_rule %s: unknown capability %q", rule.ID, t.Capability)
			}
			for _, g := range t.RequiredGranularity {
				if !r.HasGranularity(g) {
					return fmt.Errorf("compiler_rule %s: unknown granularity %q", rule.ID, g)
				}
			}
		}
	}

	return nil
}
