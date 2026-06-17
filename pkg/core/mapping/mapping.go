// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package mapping defines the RequirementMapping — the explicit, versioned
// translation table that tells the compiler how each canonical requirement
// maps to a target-specific construct.
//
// A RequirementMapping is NOT generated automatically. It must be authored and
// reviewed, and lives in Git as part of the Enterprise PAP. This ensures that
// semantic translations are always intentional and auditable.
//
// The mapping is separate from the CapabilityManifest: the manifest says what
// a target *can* do in principle; the mapping says *how* to translate a
// specific policy condition for that target.
package mapping

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// RequirementMapping is the top-level mapping document for a single target.
//
// Example YAML:
//
//	apiVersion: kernloom.io/v1
//	kind: RequirementMapping
//	metadata:
//	  name: openziti-mapping
//	  target: openziti
//	spec:
//	  version: "1.0"
//	  rules:
//	    - requirementKind: subject_identity
//	      targetField: service_policy.identity_attributes
//	      translationNote: "Map role ref to OpenZiti identity attribute tag"
//	    - requirementKind: auth_strength
//	      targetField: delegated
//	      delegationMode: vendor_runtime
//	      translationNote: "MFA enforced by OpenZiti controller; not directly configurable per-policy"
type RequirementMapping struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	Metadata   MappingMetadata `yaml:"metadata"`
	Spec       MappingSpec     `yaml:"spec"`
}

// MappingMetadata identifies the requirement mapping document.
type MappingMetadata struct {
	Name   string `yaml:"name"`
	Target string `yaml:"target"` // must match the CapabilityManifest metadata.name
}

// MappingSpec is the normative body of a RequirementMapping.
type MappingSpec struct {
	Version string        `yaml:"version"`
	Rules   []MappingRule `yaml:"rules"`
}

// DelegationMode describes how a delegated requirement is handled.
type DelegationMode string

const (
	// DelegationVendorRuntime means the vendor's own runtime PDP evaluates this.
	DelegationVendorRuntime DelegationMode = "vendor_runtime"

	// DelegationExternalPIP means an external PIP supplies the value.
	DelegationExternalPIP DelegationMode = "external_pip"

	// DelegationNotApplicable means no delegation is involved.
	DelegationNotApplicable DelegationMode = ""
)

// MappingRule describes how a single requirement kind translates to a
// target-specific field or action.
type MappingRule struct {
	// RequirementKind is the canonical requirement Kind this rule applies to.
	// Matches the Kind constants in the requirement package.
	RequirementKind string `yaml:"requirementKind"`

	// TargetField is the vendor-native field or construct that carries this
	// requirement. Use "delegated" when no direct field exists.
	TargetField string `yaml:"targetField"`

	// DelegationMode describes how the requirement is handled when TargetField
	// is "delegated".
	DelegationMode DelegationMode `yaml:"delegationMode,omitempty"`

	// SemanticDowngrade is set when the translation loses precision.
	SemanticDowngrade *SemanticDowngrade `yaml:"semanticDowngrade,omitempty"`

	// TranslationNote is a human-readable explanation of the mapping.
	TranslationNote string `yaml:"translationNote,omitempty"`
}

// SemanticDowngrade documents the precision loss in a mapping rule.
type SemanticDowngrade struct {
	// From describes the enterprise-level semantic.
	From string `yaml:"from"`

	// To describes the reduced target-level semantic.
	To string `yaml:"to"`

	// Reason explains why the downgrade is unavoidable.
	Reason string `yaml:"reason"`
}

// RuleFor returns the MappingRule for a given requirement kind.
// Returns nil if no rule exists for that kind.
func (m *RequirementMapping) RuleFor(kind string) *MappingRule {
	for i := range m.Spec.Rules {
		if m.Spec.Rules[i].RequirementKind == kind {
			return &m.Spec.Rules[i]
		}
	}
	return nil
}

// Validate performs basic structural checks on a RequirementMapping.
func (m *RequirementMapping) Validate() error {
	if m.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if m.Kind != "RequirementMapping" {
		return fmt.Errorf("kind must be RequirementMapping, got %q", m.Kind)
	}
	if m.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if m.Metadata.Target == "" {
		return fmt.Errorf("metadata.target is required")
	}
	for i, r := range m.Spec.Rules {
		if r.RequirementKind == "" {
			return fmt.Errorf("spec.rules[%d].requirementKind is required", i)
		}
		if r.TargetField == "" {
			return fmt.Errorf("spec.rules[%d].targetField is required", i)
		}
	}
	return nil
}

// LoadFromFile parses a RequirementMapping from a YAML file.
func LoadFromFile(path string) (*RequirementMapping, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses a RequirementMapping from raw YAML bytes.
func Parse(data []byte) (*RequirementMapping, error) {
	var m RequirementMapping
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing RequirementMapping: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("invalid RequirementMapping: %w", err)
	}
	return &m, nil
}
