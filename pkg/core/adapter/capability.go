// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package adapter defines the AdapterCapabilityManifest — what a target
// product can do, at the product level.
//
// This is stable, vendor-specific knowledge. It describes capabilities,
// roles, and what categories of operations exist. It does NOT contain:
//   - deployment-specific ownership       → TargetIntegrationProfile
//   - policy-specific coverage/downgrades → EnforcementPlan (compiler output)
//   - runtime action execution rules       → RuntimeActionCatalog
package adapter

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// TargetType classifies the category of the target product.
type TargetType string

const (
	TargetTypeVendorSubControlPlane TargetType = "vendor_sub_control_plane"
	TargetTypeLocalPEP              TargetType = "local_pep"
	TargetTypeIdentitySystem        TargetType = "identity_system"
	TargetTypeNetworkDevice         TargetType = "network_device"
	TargetTypeWorkloadPlatform      TargetType = "workload_platform"
)

// TargetRole describes a functional role the target can fulfil.
type TargetRole string

const (
	RoleVendorPAP        TargetRole = "vendor_pap"         // manages its own config
	RoleVendorRuntimePDP TargetRole = "vendor_runtime_pdp" // makes runtime decisions
	RoleVendorPEP        TargetRole = "vendor_pep"         // enforces access
	RolePIPRead          TargetRole = "pip_read"            // supplies signals/telemetry
	RoleKernloomPEP      TargetRole = "kernloom_pep"       // pure enforcement, no policy logic
)

// CapabilityEffect classifies whether an action capability is always
// restrictive (reduces access) or context-dependent.
type CapabilityEffect string

const (
	EffectRestrictive      CapabilityEffect = "restrictive"
	EffectContextDependent CapabilityEffect = "context_dependent"
)

// CapabilitySupport declares whether a capability is unconditionally
// available or only under certain conditions.
type CapabilitySupport string

const (
	SupportUnconditional CapabilitySupport = "unconditional"
	SupportConditional   CapabilitySupport = "conditional"
)

// AdapterCapabilityManifest is the top-level product-level capability
// declaration. One file per adapter; shared across all deployment profiles.
//
// Example YAML:
//
//	apiVersion: kernloom.io/v1alpha1
//	kind: AdapterCapabilityManifest
//	metadata:
//	  name: openziti
//	  version: "1.0"
//	spec:
//	  targetType: vendor_sub_control_plane
//	  roles: [vendor_pap, vendor_runtime_pdp, vendor_pep, pip_read]
//	  capabilities:
//	    - id: identity.role_attributes
//	      category: identity
//	      operations: [read, write]
type AdapterCapabilityManifest struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	Metadata   AdapterMetadata `yaml:"metadata"`
	Spec       AdapterSpec     `yaml:"spec"`
}

// AdapterMetadata identifies the capability manifest.
type AdapterMetadata struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version,omitempty"`
}

// AdapterSpec is the normative body of an AdapterCapabilityManifest.
type AdapterSpec struct {
	TargetType   TargetType          `yaml:"targetType"`
	Roles        []TargetRole        `yaml:"roles"`
	Capabilities []AdapterCapability `yaml:"capabilities"`
}

// AdapterCapability describes one capability the target product provides.
type AdapterCapability struct {
	// ID is the canonical capability identifier, e.g. "identity.role_attributes".
	ID string `yaml:"id"`

	// Category groups the capability: identity, access_control, posture,
	// authentication, resource_identity, runtime_authorization, runtime_action.
	Category string `yaml:"category"`

	// Operations lists what can be done: read, write, create, update, delete.
	// Absent means the capability is evaluated/enforced, not CRUD.
	Operations []string `yaml:"operations,omitempty"`

	// EvaluationOwner declares who evaluates this capability at runtime.
	// "vendor" = evaluated internally by the target's own systems.
	// "kernloom" = Kernloom's runtime PDP evaluates.
	EvaluationOwner string `yaml:"evaluationOwner,omitempty"`

	// EnforcementOwner declares who enforces the decision.
	EnforcementOwner string `yaml:"enforcementOwner,omitempty"`

	// Effect classifies action capabilities: restrictive means the action
	// can only reduce access, never widen it.
	Effect CapabilityEffect `yaml:"effect,omitempty"`

	// Support declares availability: unconditional or conditional.
	Support CapabilitySupport `yaml:"support,omitempty"`
}

// CapabilityByID returns the capability with the given ID, or nil.
func (m *AdapterCapabilityManifest) CapabilityByID(id string) *AdapterCapability {
	for i := range m.Spec.Capabilities {
		if m.Spec.Capabilities[i].ID == id {
			return &m.Spec.Capabilities[i]
		}
	}
	return nil
}

// HasCapability returns true if a capability with the given ID is declared.
func (m *AdapterCapabilityManifest) HasCapability(id string) bool {
	return m.CapabilityByID(id) != nil
}

// Validate performs basic structural checks.
func (m *AdapterCapabilityManifest) Validate() error {
	if m.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if m.Kind != "AdapterCapabilityManifest" {
		return fmt.Errorf("kind must be AdapterCapabilityManifest, got %q", m.Kind)
	}
	if m.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if m.Spec.TargetType == "" {
		return fmt.Errorf("spec.targetType is required")
	}
	return nil
}

// LoadFromFile parses an AdapterCapabilityManifest from a YAML file.
func LoadFromFile(path string) (*AdapterCapabilityManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses an AdapterCapabilityManifest from raw YAML bytes.
func Parse(data []byte) (*AdapterCapabilityManifest, error) {
	var m AdapterCapabilityManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing AdapterCapabilityManifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("invalid AdapterCapabilityManifest: %w", err)
	}
	return &m, nil
}
