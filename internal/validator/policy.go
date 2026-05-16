// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package validator

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kernloom/kernloom-forge/internal/registry"
)

// PolicyBinding resolves a named variable for use in a CEL expression.
// from: "signal" requires id + scope.
// from: "baseline" requires signal + scope + statistic.
type PolicyBinding struct {
	From      string `yaml:"from"`
	ID        string `yaml:"id"`       // for from: signal
	Signal    string `yaml:"signal"`   // for from: baseline
	Scope     string `yaml:"scope"`
	Statistic string `yaml:"statistic"` // for from: baseline
}

// PolicyWhen holds the condition block of a policy.
type PolicyWhen struct {
	Language   string                   `yaml:"language"`
	Expression string                   `yaml:"expression"`
	Bindings   map[string]PolicyBinding `yaml:"bindings"`
	// Legacy simple matchers (non-CEL) for backward compat.
	All []map[string]any `yaml:"all"`
	Any []map[string]any `yaml:"any"`
}

// PolicyRequirements declares the technical prerequisites a policy needs
// from the adapter(s) selected by the compiler.
type PolicyRequirements struct {
	RequiredCapabilities []string `yaml:"required_capabilities"`
	MinGranularity       []string `yaml:"min_granularity"`
	SemanticDepth        string   `yaml:"semantic_depth"`
	Degradation          struct {
		Allow                  bool     `yaml:"allow"`
		AcceptableGranularities []string `yaml:"acceptable_granularities"`
		RequireApproval        bool     `yaml:"require_approval"`
	} `yaml:"degradation"`
}

// BaselineRequirements declares which baseline signal the policy depends on.
type BaselineRequirements struct {
	Signal          string   `yaml:"signal"`
	PreferredScopes []string `yaml:"preferred_scopes"`
	MinConfidence   float64  `yaml:"min_confidence"`
	FallbackAllowed bool     `yaml:"fallback_allowed"`
}

// PolicyAction represents a single then: action in a policy.
type PolicyAction struct {
	Type       string         `yaml:"type"`
	Capability string         `yaml:"capability"`
	Intent     string         `yaml:"intent"`
	Target     map[string]any `yaml:"target"`
	Parameters map[string]any `yaml:"parameters"`
	TTL        string         `yaml:"ttl"`
	Reason     string         `yaml:"reason"`
}

// Policy is the parsed form of any policy kind.
type Policy struct {
	Kind       string `yaml:"kind"`
	APIVersion string `yaml:"apiVersion"`
	Metadata   struct {
		ID          string `yaml:"id"`
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	} `yaml:"metadata"`
	Intent               string               `yaml:"intent"`
	Target               map[string]any       `yaml:"target"`
	Requirements         PolicyRequirements   `yaml:"requirements"`
	BaselineRequirements BaselineRequirements `yaml:"baseline_requirements"`
	When                 PolicyWhen           `yaml:"when"`
	Then                 []PolicyAction       `yaml:"then"`
}

// bindingNameRe matches valid CEL identifiers (used as binding variable names).
var bindingNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// ParsePolicyFile parses a policy file without validating it against the registry.
func ParsePolicyFile(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read %s: %w", path, err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return p, nil
}

// ValidatePolicyFile loads and validates a single policy file.
func ValidatePolicyFile(path string, reg *registry.Registry) error {
	p, err := ParsePolicyFile(path)
	if err != nil {
		return err
	}
	return ValidatePolicy(&p, reg)
}

// ValidatePolicy validates a parsed Policy against the registry.
func ValidatePolicy(p *Policy, reg *registry.Registry) error {
	if p.Metadata.ID == "" {
		return fmt.Errorf("policy missing metadata.id")
	}

	validKinds := map[string]bool{
		"RuntimePolicy":     true,
		"AccessPolicy":      true,
		"BaselinePolicy":    true,
		"EnforcementPolicy": true,
		"ExportPolicy":      true,
	}
	if !validKinds[p.Kind] {
		return fmt.Errorf("policy %s: unknown kind %q", p.Metadata.ID, p.Kind)
	}

	// Top-level intent reference.
	if p.Intent != "" {
		if strings.HasPrefix(p.Intent, "x.") {
			return fmt.Errorf("policy %s: extension intent %q not allowed in strict mode", p.Metadata.ID, p.Intent)
		}
		if !reg.HasIntent(p.Intent) {
			return fmt.Errorf("policy %s: unknown intent %q", p.Metadata.ID, p.Intent)
		}
	}

	// Validate requirements block.
	if err := validatePolicyRequirements(p, reg); err != nil {
		return err
	}

	// Validate baseline_requirements block.
	if err := validateBaselineRequirements(p, reg); err != nil {
		return err
	}

	// Validate when: block.
	if err := validateWhen(p, reg); err != nil {
		return err
	}

	// Validate then: actions.
	for i, action := range p.Then {
		if err := validateAction(p.Metadata.ID, i, &action, reg); err != nil {
			return err
		}
	}

	return nil
}

func validatePolicyRequirements(p *Policy, reg *registry.Registry) error {
	for _, capID := range p.Requirements.RequiredCapabilities {
		if strings.HasPrefix(capID, "x.") {
			return fmt.Errorf("policy %s: extension capability %q in requirements not allowed", p.Metadata.ID, capID)
		}
		if !reg.HasCapability(capID) {
			return fmt.Errorf("policy %s: requirements references unknown capability %q", p.Metadata.ID, capID)
		}
	}
	for _, g := range p.Requirements.MinGranularity {
		if !reg.HasGranularity(g) {
			return fmt.Errorf("policy %s: requirements.min_granularity references unknown granularity %q", p.Metadata.ID, g)
		}
	}
	for _, g := range p.Requirements.Degradation.AcceptableGranularities {
		if !reg.HasGranularity(g) {
			return fmt.Errorf("policy %s: degradation.acceptable_granularities references unknown granularity %q", p.Metadata.ID, g)
		}
	}
	return nil
}

func validateBaselineRequirements(p *Policy, reg *registry.Registry) error {
	if p.BaselineRequirements.Signal == "" {
		return nil
	}
	if !reg.HasSignal(p.BaselineRequirements.Signal) {
		return fmt.Errorf("policy %s: baseline_requirements.signal references unknown signal %q",
			p.Metadata.ID, p.BaselineRequirements.Signal)
	}
	for _, sc := range p.BaselineRequirements.PreferredScopes {
		if !reg.HasScope(sc) && !reg.HasGranularity(sc) {
			return fmt.Errorf("policy %s: baseline_requirements.preferred_scopes references unknown scope %q",
				p.Metadata.ID, sc)
		}
	}
	return nil
}

func validateWhen(p *Policy, reg *registry.Registry) error {
	// Validate named bindings (CEL variable declarations).
	for name, binding := range p.When.Bindings {
		if !bindingNameRe.MatchString(name) {
			return fmt.Errorf("policy %s: binding name %q is not a valid identifier", p.Metadata.ID, name)
		}
		if err := validateBinding(p.Metadata.ID, name, &binding, reg); err != nil {
			return err
		}
	}

	// Legacy simple matchers.
	if p.When.Language == "" || p.When.Language == "simple" {
		for _, cond := range append(p.When.All, p.When.Any...) {
			if sig, ok := cond["signal"].(string); ok && sig != "" {
				if strings.HasPrefix(sig, "x.") {
					return fmt.Errorf("policy %s: extension signal %q in condition not allowed in strict mode", p.Metadata.ID, sig)
				}
				if !reg.HasSignal(sig) {
					return fmt.Errorf("policy %s: condition references unknown signal %q", p.Metadata.ID, sig)
				}
			}
		}
	}
	// CEL expressions are accepted syntactically as-is; type-checking planned for Phase 3.

	return nil
}

func validateBinding(policyID, name string, b *PolicyBinding, reg *registry.Registry) error {
	switch b.From {
	case "signal":
		if b.ID == "" {
			return fmt.Errorf("policy %s binding %q: from:signal requires id", policyID, name)
		}
		if !reg.HasSignal(b.ID) {
			return fmt.Errorf("policy %s binding %q: references unknown signal %q", policyID, name, b.ID)
		}
		if b.Scope != "" && !reg.HasScope(b.Scope) && !reg.HasGranularity(b.Scope) {
			return fmt.Errorf("policy %s binding %q: references unknown scope %q", policyID, name, b.Scope)
		}

	case "baseline":
		if b.Signal == "" {
			return fmt.Errorf("policy %s binding %q: from:baseline requires signal", policyID, name)
		}
		if !reg.HasSignal(b.Signal) {
			return fmt.Errorf("policy %s binding %q: references unknown signal %q", policyID, name, b.Signal)
		}
		if b.Scope == "" {
			return fmt.Errorf("policy %s binding %q: from:baseline requires scope", policyID, name)
		}
		if !reg.HasScope(b.Scope) && !reg.HasGranularity(b.Scope) {
			return fmt.Errorf("policy %s binding %q: references unknown scope %q", policyID, name, b.Scope)
		}
		if b.Statistic == "" {
			return fmt.Errorf("policy %s binding %q: from:baseline requires statistic", policyID, name)
		}
		if !reg.HasBaselineStatistic(b.Statistic) {
			return fmt.Errorf("policy %s binding %q: references unknown baseline_statistic %q", policyID, name, b.Statistic)
		}

	case "":
		return fmt.Errorf("policy %s binding %q: missing from (signal or baseline)", policyID, name)

	default:
		return fmt.Errorf("policy %s binding %q: unknown from value %q (must be signal or baseline)", policyID, name, b.From)
	}
	return nil
}

func validateAction(policyID string, idx int, a *PolicyAction, reg *registry.Registry) error {
	switch a.Type {
	case "capability_action":
		if a.Capability == "" {
			return fmt.Errorf("policy %s action[%d]: capability_action missing capability", policyID, idx)
		}
		if strings.HasPrefix(a.Capability, "x.") {
			return fmt.Errorf("policy %s action[%d]: extension capability %q not allowed in strict mode", policyID, idx, a.Capability)
		}
		if !reg.HasCapability(a.Capability) {
			return fmt.Errorf("policy %s action[%d]: unknown capability %q", policyID, idx, a.Capability)
		}

	case "intent_action":
		if a.Intent == "" {
			return fmt.Errorf("policy %s action[%d]: intent_action missing intent", policyID, idx)
		}
		if strings.HasPrefix(a.Intent, "x.") {
			return fmt.Errorf("policy %s action[%d]: extension intent %q not allowed in strict mode", policyID, idx, a.Intent)
		}
		if !reg.HasIntent(a.Intent) {
			return fmt.Errorf("policy %s action[%d]: unknown intent %q", policyID, idx, a.Intent)
		}

	case "event_action", "export_action", "audit_action", "suppress_action":
		// Valid action types — content validation in later phases.

	case "":
		return fmt.Errorf("policy %s action[%d]: missing type", policyID, idx)

	default:
		return fmt.Errorf("policy %s action[%d]: unknown action type %q", policyID, idx, a.Type)
	}

	return nil
}
