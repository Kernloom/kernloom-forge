// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package profile defines the TargetIntegrationProfile — how a specific
// deployment uses an adapter.
//
// One profile per deployment environment (openziti-production,
// openziti-staging, idp-hybrid-prod, etc.). Multiple profiles can reference
// the same AdapterCapabilityManifest via adapterRef.
//
// The profile answers:
//   - Which integration mode? (config_only, enterprise_risk_overlay, ...)
//   - Who owns each concern in this deployment? (named entities)
//   - What are the runtime constraints? (TTL required, lease required, ...)
//   - Which runtime actions are permitted in this deployment?
package profile

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// IntegrationMode describes the relationship between Kernloom and the target
// at runtime.
type IntegrationMode string

const (
	// ModeConfigOnly: Kernloom writes durable configuration. The target owns
	// all runtime context, decision making, and enforcement. No Kernloom
	// runtime component is involved after config deployment.
	ModeConfigOnly IntegrationMode = "config_only"

	// ModeEnterpriseRiskOverlay: Target remains the in-path authorization
	// owner (evaluates its own policies on every connection). Kernloom's Risk
	// Engine evaluates enterprise signals out-of-band and may issue
	// TTL-bounded restrictions via the action adapter when risk thresholds
	// are exceeded.
	//
	// Final access = target_policy_allows AND NOT kernloom_restriction_active
	//
	// Kernloom may only RESTRICT, never grant additional access.
	// Decision timing: near-runtime. Path: out-of-band. Convergence: eventual.
	ModeEnterpriseRiskOverlay IntegrationMode = "enterprise_risk_overlay"

	// ModeKernloomPDPNative: Kernloom Runtime PDP is the sole in-path
	// decision point. The target is a pure enforcement agent with no
	// independent policy logic (e.g. KLShield).
	ModeKernloomPDPNative IntegrationMode = "kernloom_pdp_native"
)

// RuntimeTiming describes when Kernloom's enforcement decisions take effect.
type RuntimeTiming string

const (
	TimingNearRuntime RuntimeTiming = "near_runtime" // seconds to minutes
	TimingCompileTime RuntimeTiming = "compile_time" // only at config deployment
	TimingInPath      RuntimeTiming = "in_path"      // synchronous, per connection
)

// RuntimePath describes how Kernloom communicates decisions to the target.
type RuntimePath string

const (
	PathOutOfBand RuntimePath = "out_of_band" // via management API, async
	PathInPath    RuntimePath = "in_path"     // inline, synchronous
)

// RuntimeComposition describes how Kernloom and the target decisions combine.
type RuntimeComposition string

const (
	// CompositionRestrictiveAnd: access is allowed only if BOTH the target's
	// own policy allows AND no Kernloom restriction is active.
	// Kernloom can only restrict, never grant.
	CompositionRestrictiveAnd RuntimeComposition = "restrictive_and"

	// CompositionKernloomOnly: Kernloom Runtime PDP is the sole decision
	// point. Target is pure enforcement.
	CompositionKernloomOnly RuntimeComposition = "kernloom_only"

	// CompositionVendorOnly: vendor owns all runtime decisions.
	CompositionVendorOnly RuntimeComposition = "vendor_only"
)

// TargetIntegrationProfile is the top-level deployment-specific declaration.
// It binds an AdapterCapabilityManifest to a concrete operational context.
type TargetIntegrationProfile struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	Metadata   ProfileMetadata `yaml:"metadata"`
	Spec       ProfileSpec     `yaml:"spec"`
}

// ProfileMetadata identifies the integration profile.
type ProfileMetadata struct {
	Name string `yaml:"name"`
}

// ProfileSpec is the normative body of a TargetIntegrationProfile.
type ProfileSpec struct {
	// AdapterRef references the AdapterCapabilityManifest by metadata.name.
	AdapterRef string `yaml:"adapterRef"`

	// Mode declares the integration pattern.
	Mode IntegrationMode `yaml:"mode"`

	// SourceOfTruth declares who owns durable policy and desired state.
	SourceOfTruth SourceOfTruth `yaml:"sourceOfTruth"`

	// Ownership maps each enforcement concern to its named owner in this
	// deployment. Owners are concrete component names, not generic tokens.
	Ownership ProfileOwnership `yaml:"ownership"`

	// Runtime describes the runtime characteristics of this integration.
	Runtime RuntimeSpec `yaml:"runtime,omitempty"`

	// AllowedRuntimeActions lists the action IDs from the RuntimeActionCatalog
	// that are permitted in this deployment. If empty, no runtime actions are
	// allowed (config_only behavior regardless of catalog content).
	AllowedRuntimeActions []string `yaml:"allowedRuntimeActions,omitempty"`
}

// SourceOfTruth declares authoritative sources for policy and desired state.
type SourceOfTruth struct {
	Policy       string `yaml:"policy"`       // e.g. "git"
	DesiredState string `yaml:"desiredState"` // e.g. "git"
}

// ProfileOwner is a named owner entry in a profile's ownership declaration.
// The owner value is a concrete deployment component name.
type ProfileOwner struct {
	Owner string `yaml:"owner"`
}

// ProfileOwnership maps each enforcement concern to its deployment owner.
// Field names map exactly to the concern model from the architecture docs.
type ProfileOwnership struct {
	// EnterpriseIntent: who authors and versions enterprise policy intent.
	EnterpriseIntent ProfileOwner `yaml:"enterpriseIntent"`

	// Compilation: who compiles policy intent into enforcement artifacts.
	Compilation ProfileOwner `yaml:"compilation"`

	// ConfigValidation: who validates config proposals (Config PDP).
	ConfigValidation ProfileOwner `yaml:"configValidation"`

	// ConfigDeployment: who deploys configuration to the target.
	ConfigDeployment ProfileOwner `yaml:"configDeployment"`

	// RiskAssessment: who aggregates signals into a risk assessment.
	// Separate from EnterpriseControlDecision.
	RiskAssessment ProfileOwner `yaml:"riskAssessment"`

	// EnterpriseControlDecision: who makes the enterprise-level allow/restrict
	// decision (e.g. Kernloom Runtime PDP).
	EnterpriseControlDecision ProfileOwner `yaml:"enterpriseControlDecision"`

	// TargetAuthorizationDecision: who makes the target's own in-path
	// authorization decision (e.g. OpenZiti controller on every dial).
	TargetAuthorizationDecision ProfileOwner `yaml:"targetAuthorizationDecision"`

	// TargetPolicyEvaluation: who evaluates the target's own policy rules.
	TargetPolicyEvaluation ProfileOwner `yaml:"targetPolicyEvaluation"`

	// Enforcement: who performs the actual data-plane allow/deny.
	Enforcement ProfileOwner `yaml:"enforcement"`
}

// RuntimeSpec describes the runtime characteristics of the integration.
type RuntimeSpec struct {
	Timing      RuntimeTiming      `yaml:"timing"`
	Path        RuntimePath        `yaml:"path"`
	Composition RuntimeComposition `yaml:"composition"`
	Constraints RuntimeConstraints `yaml:"constraints"`
}

// RuntimeConstraints declares mandatory requirements for all runtime actions
// in this deployment.
type RuntimeConstraints struct {
	RestrictiveOnly   bool `yaml:"restrictiveOnly"`
	RequireTTL        bool `yaml:"requireTTL"`
	RequireAudit      bool `yaml:"requireAudit"`
	RequireLease      bool `yaml:"requireLease"`
	RequireAutoRevert bool `yaml:"requireAutoRevert"`
}

// IsActionAllowed returns true if the given action ID is permitted in this
// profile's allowedRuntimeActions list.
func (p *TargetIntegrationProfile) IsActionAllowed(actionID string) bool {
	for _, a := range p.Spec.AllowedRuntimeActions {
		if a == actionID {
			return true
		}
	}
	return false
}

// Validate performs basic structural checks.
func (p *TargetIntegrationProfile) Validate() error {
	if p.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if p.Kind != "TargetIntegrationProfile" {
		return fmt.Errorf("kind must be TargetIntegrationProfile, got %q", p.Kind)
	}
	if p.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if p.Spec.AdapterRef == "" {
		return fmt.Errorf("spec.adapterRef is required")
	}
	if p.Spec.Mode == "" {
		return fmt.Errorf("spec.mode is required")
	}
	return nil
}

// LoadFromFile parses a TargetIntegrationProfile from a YAML file.
func LoadFromFile(path string) (*TargetIntegrationProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses a TargetIntegrationProfile from raw YAML bytes.
func Parse(data []byte) (*TargetIntegrationProfile, error) {
	var p TargetIntegrationProfile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing TargetIntegrationProfile: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid TargetIntegrationProfile: %w", err)
	}
	return &p, nil
}
