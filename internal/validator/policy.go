// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package validator

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kernloom/kernloom-forge/internal/registry"
)

// PolicyAction represents a single then: action in a policy.
type PolicyAction struct {
	Type       string         `yaml:"type"`
	Capability string         `yaml:"capability"`
	Intent     string         `yaml:"intent"`
	Target     map[string]any `yaml:"target"`
	TTL        string         `yaml:"ttl"`
	Reason     string         `yaml:"reason"`
}

// PolicyWhen holds the condition block of a policy.
type PolicyWhen struct {
	Language   string `yaml:"language"`
	Expression string `yaml:"expression"`
	// Legacy simple matchers (non-CEL) for backward compat.
	All []map[string]any `yaml:"all"`
	Any []map[string]any `yaml:"any"`
}

// Policy is the parsed form of any policy kind.
type Policy struct {
	Kind       string `yaml:"kind"`
	APIVersion string `yaml:"apiVersion"`
	Metadata   struct {
		ID          string `yaml:"id"`
		Description string `yaml:"description"`
	} `yaml:"metadata"`
	Intent string         `yaml:"intent"`
	When   PolicyWhen     `yaml:"when"`
	Then   []PolicyAction `yaml:"then"`
}

// ValidatePolicyFile loads and validates a single policy file.
func ValidatePolicyFile(path string, reg *registry.Registry) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
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

	// Top-level intent reference (e.g. AccessPolicy, BaselinePolicy).
	if p.Intent != "" {
		if strings.HasPrefix(p.Intent, "x.") {
			return fmt.Errorf("policy %s: extension intent %q not allowed in strict mode", p.Metadata.ID, p.Intent)
		}
		if !reg.HasIntent(p.Intent) {
			return fmt.Errorf("policy %s: unknown intent %q", p.Metadata.ID, p.Intent)
		}
	}

	// Validate when: block signals for non-CEL policies.
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
	// CEL expressions are accepted as-is in Phase 1 — type checking against
	// the signal registry is planned for Phase 2.

	// Validate then: actions.
	for i, action := range p.Then {
		if err := validateAction(p.Metadata.ID, i, &action, reg); err != nil {
			return err
		}
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
