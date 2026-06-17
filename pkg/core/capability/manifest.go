// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package capability defines the CapabilityManifest — the declaration each
// adapter/target publishes to tell the compiler what it can and cannot enforce.
//
// # Coverage levels
//
//  1. full           — target enforces natively and completely.
//  2. partial        — target approximates with reduced semantic fidelity (downgrade).
//  3. delegated      — target has its own internal PDP that evaluates at runtime.
//     Only valid when the vendor can evaluate an EQUIVALENT condition natively.
//     A posture check used as a proxy for enterprise risk is NOT delegation — it
//     is partial with semantic downgrade.
//  4. runtime_action — Kernloom Risk Engine + Runtime PDP enforce this requirement
//     by issuing TTL-bounded, auto-reverting actions through the target's action
//     adapter. The target continues to evaluate its own policies independently.
//  5. pip_only       — target can supply signals but cannot enforce.
//  6. unsupported    — target cannot handle this requirement.
//
// # Integration modes
//
// Each manifest declares an IntegrationMode that precisely describes how Kernloom
// and the target interact at runtime:
//
//	config_only              — Kernloom writes durable config; target owns all runtime.
//	hybrid_out_of_band       — Target owns runtime authorization; Kernloom can issue
//	                           asynchronous TTL-bounded restrictions via action adapter
//	                           when Risk Engine detects elevated risk. Decision timing:
//	                           near-runtime, out-of-band, eventual convergence.
//	kernloom_pdp_native      — Kernloom Runtime PDP is the in-path decision point.
//	                           Target is a pure enforcement layer (e.g. KLShield).
//
// # Ownership model
//
// Risk Engine and Runtime PDP are separate concerns and must not be conflated:
//
//	PIPs → Risk Engine → Risk Assessment → Runtime PDP → Policy Decision → Action
//
// Use distinct tokens for each:
//
//	riskDecisionOwner:     kernloom-risk-engine   (aggregates signals → risk fact)
//	runtimeDecisionOwner:  kernloom-runtime-pdp   (evaluates policy → allow/deny)
package capability

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// CoverageLevel describes how a target handles a given requirement kind.
type CoverageLevel string

const (
	CoverageFull          CoverageLevel = "full"
	CoveragePartial       CoverageLevel = "partial"
	CoverageDelegated     CoverageLevel = "delegated"
	CoverageRuntimeAction CoverageLevel = "runtime_action"
	CoverageUnsupported   CoverageLevel = "unsupported"
	CoveragePIPOnly       CoverageLevel = "pip_only"
)

// TargetType classifies what category of target the manifest describes.
type TargetType string

const (
	TargetTypeVendorSubControlPlane TargetType = "vendor_sub_control_plane"
	TargetTypeLocalPEP              TargetType = "local_pep"
	TargetTypeIdentitySystem        TargetType = "identity_system"
	TargetTypeNetworkDevice         TargetType = "network_device"
	TargetTypeWorkloadPlatform      TargetType = "workload_platform"
)

// IntegrationMode describes how Kernloom interacts with the target at runtime.
type IntegrationMode string

const (
	// IntegrationModeConfigOnly: Kernloom writes durable configuration.
	// The target owns all runtime context collection, risk evaluation,
	// authorization decisions, and enforcement. No Kernloom runtime component
	// is involved after config deployment.
	IntegrationModeConfigOnly IntegrationMode = "config_only"

	// IntegrationModeHybridOutOfBand: The target remains the in-path runtime
	// authorization owner (evaluates its own policies on every connection/dial).
	// Kernloom's Risk Engine evaluates enterprise signals out-of-band and can
	// issue asynchronous TTL-bounded restrictions via the action adapter when
	// risk thresholds are exceeded. The effective access is the intersection:
	//   final_access = target_policy_allows AND NOT kernloom_restriction_active
	// Decision timing: near-runtime. Decision path: out-of-band. Convergence: eventual.
	// In-flight sessions/tokens may remain active until natural expiry.
	IntegrationModeHybridOutOfBand IntegrationMode = "hybrid_out_of_band"

	// IntegrationModeKernloomPDPNative: Kernloom Runtime PDP is the sole in-path
	// policy decision point. The target is a pure enforcement agent with no
	// independent policy logic. Used for Kernloom-native targets (KLShield).
	IntegrationModeKernloomPDPNative IntegrationMode = "kernloom_pdp_native"
)

// OwnershipDeclaration maps each enforcement concern to its owner token.
// All fields use canonical tokens from owner_tokens.go.
//
// Risk Engine and Runtime PDP MUST be modelled separately:
//   - riskDecisionOwner:    who aggregates signals into a risk assessment
//   - runtimeDecisionOwner: who makes the access allow/deny/restrict decision
type OwnershipDeclaration struct {
	IntentOwner             string `yaml:"intentOwner"`
	RuntimeContextOwner     string `yaml:"runtimeContextOwner"`
	RiskDecisionOwner       string `yaml:"riskDecisionOwner"`
	RuntimeDecisionOwner    string `yaml:"runtimeDecisionOwner"`
	RuntimeStateOwner       string `yaml:"runtimeStateOwner,omitempty"`
	PolicyEvaluationOwner   string `yaml:"policyEvaluationOwner"`
	EnforcementOwner        string `yaml:"enforcementOwner"`
	ConfigOwner             string `yaml:"configOwner"`
}

// RuntimeActionDeclaration describes one TTL-bounded action the target's
// action adapter can execute. All runtime actions must be monotonically
// restrictive — they may reduce access but must never grant or widen it.
type RuntimeActionDeclaration struct {
	Action      string `yaml:"action"`
	Scope       string `yaml:"scope"`
	RequiresTTL bool   `yaml:"requiresTTL"`
	AutoRevert  bool   `yaml:"autoRevert"`
	Note        string `yaml:"note,omitempty"`
}

// DowngradeDeclaration describes a single semantic downgrade.
type DowngradeDeclaration struct {
	Requirement string `yaml:"requirement"`
	From        string `yaml:"from"`
	To          string `yaml:"to"`
	Reason      string `yaml:"reason"`
}

// CapabilityManifest is the top-level declaration an adapter publishes.
type CapabilityManifest struct {
	APIVersion string           `yaml:"apiVersion"`
	Kind       string           `yaml:"kind"`
	Metadata   ManifestMetadata `yaml:"metadata"`
	Spec       ManifestSpec     `yaml:"spec"`
}

// ManifestMetadata identifies the capability manifest.
type ManifestMetadata struct {
	Name    string            `yaml:"name"`
	Version string            `yaml:"version,omitempty"`
	Labels  map[string]string `yaml:"labels,omitempty"`
}

// ManifestSpec is the normative body of a CapabilityManifest.
type ManifestSpec struct {
	TargetType      TargetType      `yaml:"targetType"`
	IntegrationMode IntegrationMode `yaml:"integrationMode"`

	// AdapterRef is the adapter/mapping package name to use for requirement
	// mapping lookup. Defaults to metadata.name when empty. Set this when
	// the manifest name differs from the mapping target, e.g.:
	//   metadata.name: openziti-config-only
	//   adapterRef:    openziti
	AdapterRef string `yaml:"adapterRef,omitempty"`

	// Legacy simple fields — use Ownership for granular per-concern declarations.
	RuntimeOwner string `yaml:"runtimeOwner,omitempty"`
	ConfigOwner  string `yaml:"configOwner,omitempty"`

	Ownership           *OwnershipDeclaration      `yaml:"ownership,omitempty"`
	RequirementCoverage map[string]CoverageLevel    `yaml:"requirementCoverage"`
	DelegationNotes     map[string]string           `yaml:"delegationNotes,omitempty"`
	Downgrades          []DowngradeDeclaration      `yaml:"downgrades,omitempty"`
	RuntimeActions      []RuntimeActionDeclaration  `yaml:"runtimeActions,omitempty"`
}

// CoverageFor returns the coverage level for a requirement kind.
// Returns CoverageUnsupported if not declared.
func (m *CapabilityManifest) CoverageFor(kind string) CoverageLevel {
	if m.Spec.RequirementCoverage == nil {
		return CoverageUnsupported
	}
	if c, ok := m.Spec.RequirementCoverage[kind]; ok {
		return c
	}
	return CoverageUnsupported
}

// RuntimeDecisionOwner returns the effective runtime decision owner,
// preferring the granular Ownership declaration.
func (m *CapabilityManifest) RuntimeDecisionOwner() string {
	if m.Spec.Ownership != nil && m.Spec.Ownership.RuntimeDecisionOwner != "" {
		return m.Spec.Ownership.RuntimeDecisionOwner
	}
	return m.Spec.RuntimeOwner
}

// MappingKey returns the name to use when looking up a RequirementMapping.
// Uses AdapterRef when set, otherwise falls back to metadata.name.
// This decouples manifest naming variants (e.g. "openziti-config-only")
// from their shared adapter mapping (e.g. "openziti").
func (m *CapabilityManifest) MappingKey() string {
	if m.Spec.AdapterRef != "" {
		return m.Spec.AdapterRef
	}
	return m.Metadata.Name
}

// Validate performs basic structural checks.
func (m *CapabilityManifest) Validate() error {
	if m.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if m.Kind != "CapabilityManifest" {
		return fmt.Errorf("kind must be CapabilityManifest, got %q", m.Kind)
	}
	if m.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if m.Spec.TargetType == "" {
		return fmt.Errorf("spec.targetType is required")
	}
	if m.Spec.IntegrationMode == "" {
		return fmt.Errorf("spec.integrationMode is required")
	}
	hasRuntimeAction := false
	for _, cov := range m.Spec.RequirementCoverage {
		if cov == CoverageRuntimeAction {
			hasRuntimeAction = true
			break
		}
	}
	if hasRuntimeAction && len(m.Spec.RuntimeActions) == 0 {
		return fmt.Errorf("spec.runtimeActions is required when any requirementCoverage uses runtime_action")
	}
	return nil
}

// LoadFromFile parses a CapabilityManifest from a YAML file.
func LoadFromFile(path string) (*CapabilityManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses a CapabilityManifest from raw YAML bytes.
func Parse(data []byte) (*CapabilityManifest, error) {
	var m CapabilityManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing CapabilityManifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("invalid CapabilityManifest: %w", err)
	}
	return &m, nil
}
