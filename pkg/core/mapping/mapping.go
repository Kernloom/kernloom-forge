// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package mapping defines the RequirementMappingSet — how canonical
// enterprise requirements translate to adapter-specific capabilities.
//
// A RequirementMappingSet lives at the adapter level (shared across profiles)
// and answers per requirement kind:
//   - full              — capability natively and fully enforces the requirement
//   - partial           — capability approximates with reduced semantic fidelity
//   - delegated         — vendor's own PDP evaluates an equivalent condition natively
//   - compensating_control — vendor cannot evaluate the requirement; Kernloom
//     compensates via a TTL-bounded restrictive runtime action
//   - unsupported       — no available mapping; requirement cannot be satisfied
//
// The distinction between delegated and compensating_control is critical:
//
//	delegated = vendor evaluates a semantically equivalent condition itself
//	compensating_control = vendor has no equivalent; Kernloom acts as a side channel
package mapping

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// SupportLevel describes how well an adapter capability satisfies a requirement.
type SupportLevel string

const (
	SupportFull                SupportLevel = "full"
	SupportPartial             SupportLevel = "partial"
	SupportDelegated           SupportLevel = "delegated"
	SupportCompensatingControl SupportLevel = "compensating_control"
	SupportUnsupported         SupportLevel = "unsupported"
)

// FidelityLevel describes the semantic precision of the mapping.
type FidelityLevel string

const (
	FidelityHigh   FidelityLevel = "high"
	FidelityMedium FidelityLevel = "medium"
	FidelityLow    FidelityLevel = "low"
)

// RequirementMappingSet is the top-level adapter-level mapping document.
//
// Example YAML:
//
//	apiVersion: kernloom.io/v1alpha1
//	kind: RequirementMappingSet
//	metadata:
//	  name: openziti-mappings
//	  adapterRef: openziti
//	spec:
//	  mappings:
//	    - requirement:
//	        kind: subject_identity
//	      capability:
//	        id: identity.role_attributes
//	      support: full
//	      fidelity: high
//	    - requirement:
//	        kind: risk_level
//	      support: compensating_control
//	      fidelity: medium
//	      binding:
//	        riskAssessmentOwner: kernloom-risk-engine
//	        decisionOwner: kernloom-runtime-pdp
//	        action: remove_kernloom_access_attribute
type RequirementMappingSet struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	Metadata   MappingMetadata `yaml:"metadata"`
	Spec       MappingSetSpec  `yaml:"spec"`
}

// MappingMetadata identifies the mapping set.
type MappingMetadata struct {
	Name       string `yaml:"name"`
	AdapterRef string `yaml:"adapterRef"`
}

// MappingSetSpec holds all mapping entries.
type MappingSetSpec struct {
	Mappings []MappingEntry `yaml:"mappings"`
}

// RequirementRef identifies a canonical requirement kind (and optionally
// a specific value, e.g. auth_strength with value "mfa").
type RequirementRef struct {
	Kind  string `yaml:"kind"`
	Value string `yaml:"value,omitempty"`
}

// CapabilityRef references an adapter capability by its canonical ID.
type CapabilityRef struct {
	ID string `yaml:"id"`
}

// DelegationSpec documents a delegated requirement: the vendor's own component
// evaluates a semantically equivalent condition at runtime.
type DelegationSpec struct {
	EvaluationOwner string `yaml:"evaluationOwner"`
	Note            string `yaml:"note,omitempty"`
}

// CompensatingBinding documents a compensating control: the requirement
// cannot be evaluated by the vendor natively; Kernloom compensates by
// issuing a TTL-bounded restrictive action when the condition is violated.
type CompensatingBinding struct {
	RiskAssessmentOwner string `yaml:"riskAssessmentOwner"`
	DecisionOwner       string `yaml:"decisionOwner"`
	Action              string `yaml:"action"`
	// Attribute is the vendor-specific object the action targets, if applicable.
	// For OpenZiti: the role attribute to remove (e.g. "kl.access.active").
	Attribute string `yaml:"attribute,omitempty"`
}

// DowngradeNote documents the semantic precision loss when support is partial.
type DowngradeNote struct {
	From   string `yaml:"from"`
	To     string `yaml:"to"`
	Reason string `yaml:"reason"`
}

// MappingEntry declares the mapping for one requirement kind.
type MappingEntry struct {
	// Requirement identifies the canonical requirement this entry covers.
	Requirement RequirementRef `yaml:"requirement"`

	// Capability is the adapter capability that handles this requirement.
	// Omit for compensating_control (no direct capability; action compensates).
	Capability CapabilityRef `yaml:"capability,omitempty"`

	// Support declares the quality of coverage.
	Support SupportLevel `yaml:"support"`

	// Fidelity describes how precisely the adapter represents the requirement's
	// enterprise semantics. Absent when support is unsupported.
	Fidelity FidelityLevel `yaml:"fidelity,omitempty"`

	// Delegation is set when support is delegated.
	Delegation *DelegationSpec `yaml:"delegation,omitempty"`

	// Binding is set when support is compensating_control.
	Binding *CompensatingBinding `yaml:"binding,omitempty"`

	// Downgrade documents the precision loss when support is partial.
	Downgrade *DowngradeNote `yaml:"downgrade,omitempty"`

	Note string `yaml:"note,omitempty"`
}

// ForKind returns the MappingEntry for the given requirement kind.
// Returns nil if no mapping exists for that kind.
func (m *RequirementMappingSet) ForKind(kind string) *MappingEntry {
	for i := range m.Spec.Mappings {
		if m.Spec.Mappings[i].Requirement.Kind == kind {
			return &m.Spec.Mappings[i]
		}
	}
	return nil
}

// Validate performs basic structural checks.
func (m *RequirementMappingSet) Validate() error {
	if m.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if m.Kind != "RequirementMappingSet" {
		return fmt.Errorf("kind must be RequirementMappingSet, got %q", m.Kind)
	}
	if m.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if m.Metadata.AdapterRef == "" {
		return fmt.Errorf("metadata.adapterRef is required")
	}
	for i, e := range m.Spec.Mappings {
		if e.Requirement.Kind == "" {
			return fmt.Errorf("spec.mappings[%d].requirement.kind is required", i)
		}
		if e.Support == "" {
			return fmt.Errorf("spec.mappings[%d].support is required", i)
		}
		if e.Support == SupportCompensatingControl && e.Binding == nil {
			return fmt.Errorf("spec.mappings[%d] (%s): binding is required for compensating_control", i, e.Requirement.Kind)
		}
		if e.Support == SupportDelegated && e.Delegation == nil {
			return fmt.Errorf("spec.mappings[%d] (%s): delegation is required for delegated", i, e.Requirement.Kind)
		}
	}
	return nil
}

// LoadFromFile parses a RequirementMappingSet from a YAML file.
func LoadFromFile(path string) (*RequirementMappingSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses a RequirementMappingSet from raw YAML bytes.
func Parse(data []byte) (*RequirementMappingSet, error) {
	var m RequirementMappingSet
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing RequirementMappingSet: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("invalid RequirementMappingSet: %w", err)
	}
	return &m, nil
}
