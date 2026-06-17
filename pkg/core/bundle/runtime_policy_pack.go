// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package bundle defines the RuntimePolicyPack and RuntimeBundle — the
// compiled artifacts that Forge produces for KLIQ to consume.
//
// These are distinct from the EnforcementPlan (which is a governance report
// for operators and auditors). The RuntimePolicyPack is a KLIQ-executable
// artifact containing evaluated rules that the Runtime PDP applies locally.
//
// Separation of concerns:
//
//	EnforcementPlan:    for auditors/operators — "what is delegated, what downgraded?"
//	RuntimePolicyPack:  for KLIQ Runtime PDP  — "what conditions trigger what effect?"
//	RuntimeBundle:      for KLIQ agent        — signed container with pack + profile + metadata
package bundle

import "time"

// RuntimePolicyPack is a Forge-compiled, KLIQ-executable policy artifact.
//
// It is NOT enterprise policy intent (that lives in Git as AccessPolicy).
// It is a compiled, per-node target artifact ready for the Runtime PDP to evaluate.
//
// KLIQ evaluates RuntimePolicyPack rules against local context facts and risk
// assessments. The pack must not contain vendor-specific field names.
//
// Example YAML:
//
//	apiVersion: kernloom.io/policy/runtime/v1alpha1
//	kind: RuntimePolicyPack
//	metadata:
//	  name: protect-investor-api
//	  generation: 42
//	  sourcePolicy: investors-to-investor-apps
//	  sourceCommit: 8a91f0c
//	spec:
//	  policies:
//	    - id: restrict-on-high-risk
//	      scope:
//	        type: protected_resource
//	        ref: service:investor-api
//	      when:
//	        language: cel
//	        expression: "risk.level in ['high','critical'] && risk.confidence >= 0.80"
//	      effect:
//	        capability: access.restrict.identity
//	        ttl: 30m
//	      missingContextBehavior: observe_only
//	      reasonCode: ENTERPRISE_RISK_HIGH
type RuntimePolicyPack struct {
	APIVersion string             `yaml:"apiVersion" json:"apiVersion"`
	Kind       string             `yaml:"kind"       json:"kind"`
	Metadata   PackMeta           `yaml:"metadata"   json:"metadata"`
	Spec       RuntimePackSpec    `yaml:"spec"       json:"spec"`
}

// PackMeta identifies the policy pack.
type PackMeta struct {
	Name         string `yaml:"name"         json:"name"`
	Generation   int64  `yaml:"generation"   json:"generation"`
	SourcePolicy string `yaml:"sourcePolicy" json:"sourcePolicy"`
	SourceCommit string `yaml:"sourceCommit,omitempty" json:"sourceCommit,omitempty"`
}

// RuntimePackSpec is the normative body of a RuntimePolicyPack.
type RuntimePackSpec struct {
	// Policies are the compiled runtime rules.
	Policies []RuntimePolicy `yaml:"policies" json:"policies"`
}

// RuntimePolicy is a single compiled rule the KLIQ Runtime PDP evaluates.
type RuntimePolicy struct {
	// ID is the unique rule identifier within this pack.
	ID string `yaml:"id" json:"id"`

	// Scope defines what resource or subject this rule protects.
	Scope PolicyScope `yaml:"scope" json:"scope"`

	// When is the CEL condition that must be true for the effect to apply.
	// Bindings are resolved from local RiskAssessment and ContextFacts.
	When PolicyWhen `yaml:"when" json:"when"`

	// Effect describes what KLIQ should do when the condition is met.
	Effect PolicyEffect `yaml:"effect" json:"effect"`

	// MissingContextBehavior defines what the PDP does when required signals
	// are absent: "deny", "observe_only", "require_step_up", "allow_with_audit".
	MissingContextBehavior string `yaml:"missingContextBehavior" json:"missingContextBehavior"`

	// ReasonCode is a machine-readable reason emitted in decisions and receipts.
	ReasonCode string `yaml:"reasonCode" json:"reasonCode"`
}

// PolicyScope identifies what this rule protects.
type PolicyScope struct {
	// Type: "protected_resource", "subject", "service", "network_source"
	Type string `yaml:"type" json:"type"`

	// Ref is the entity reference (e.g. "service:investor-api").
	Ref string `yaml:"ref,omitempty" json:"ref,omitempty"`
}

// PolicyWhen contains the CEL expression evaluated by the Runtime PDP.
//
// Available CEL variables (resolved by KLIQ from local state):
//
//	risk.level       — string: "low", "medium", "high", "critical", "unknown"
//	risk.score       — int: 0-100
//	risk.confidence  — float: 0.0-1.0
//	risk.completeness — float: 0.0-1.0
//	subject.role     — string
//	device.posture   — string: "healthy", "degraded", "unhealthy", "unknown"
//	session.auth_strength — string
type PolicyWhen struct {
	Language   string `yaml:"language"   json:"language"`   // "cel"
	Expression string `yaml:"expression" json:"expression"`
}

// PolicyEffect declares what capability to invoke and with what parameters.
type PolicyEffect struct {
	// Capability is the canonical Kernloom capability ID.
	// Examples: "access.restrict.identity", "network.rate_limit", "network.deny"
	Capability string `yaml:"capability" json:"capability"`

	// Intensity: "soft", "hard", "block" — calibrates the enforcement level.
	// Empty means the adapter picks the default.
	Intensity string `yaml:"intensity,omitempty" json:"intensity,omitempty"`

	// TTL is how long the enforcement action should remain active.
	TTL time.Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`

	// Params are additional parameters for the adapter.
	Params map[string]string `yaml:"params,omitempty" json:"params,omitempty"`
}

// RuntimePDPProfile is Forge's declaration of what KLIQ may do autonomously.
// It bounds the local decision authority so that KLIQ cannot exceed what
// the enterprise policy intends.
type RuntimePDPProfile struct {
	APIVersion string          `yaml:"apiVersion" json:"apiVersion"`
	Kind       string          `yaml:"kind"       json:"kind"`
	Metadata   ProfileMeta     `yaml:"metadata"   json:"metadata"`
	Spec       PDPProfileSpec  `yaml:"spec"       json:"spec"`
}

// ProfileMeta identifies the PDP profile.
type ProfileMeta struct {
	Name string `yaml:"name" json:"name"`
}

// PDPProfileSpec declares the bounds for KLIQ's local autonomy.
type PDPProfileSpec struct {
	// LocalRiskMode declares which risk modes are permitted.
	// Values: "none", "cached_global", "local_lite", "local_full", "hybrid"
	LocalRiskMode string `yaml:"localRiskMode" json:"localRiskMode"`

	// RiskModelRef pins the risk model version KLIQ must use locally.
	RiskModelRef RiskModelRef `yaml:"riskModelRef" json:"riskModelRef"`

	// AllowedCapabilities lists the capability IDs KLIQ may invoke.
	// KLIQ must reject any decision that requests an unlisted capability.
	AllowedCapabilities []string `yaml:"allowedCapabilities" json:"allowedCapabilities"`

	// MaxActionIntensity caps the enforcement intensity: "soft", "hard", "block".
	MaxActionIntensity string `yaml:"maxActionIntensity" json:"maxActionIntensity"`

	// MaxTTL is the maximum TTL for any single enforcement action.
	MaxTTL time.Duration `yaml:"maxTTL" json:"maxTTL"`

	// AllowLocalBlock: when false, KLIQ may not issue block-level decisions
	// without Forge explicit authorisation.
	AllowLocalBlock bool `yaml:"allowLocalBlock" json:"allowLocalBlock"`

	// OfflineBehavior defines what KLIQ does when Forge is unreachable.
	// Values: "observe_only", "use_last_known_good", "fail_closed"
	OfflineBehavior string `yaml:"offlineBehavior" json:"offlineBehavior"`

	// GlobalRiskTTL is how long KLIQ may use a cached global risk assessment.
	GlobalRiskTTL time.Duration `yaml:"globalRiskTTL,omitempty" json:"globalRiskTTL,omitempty"`
}

// RiskModelRef pins a specific risk model version.
type RiskModelRef struct {
	Name    string `yaml:"name"    json:"name"`
	Version string `yaml:"version" json:"version"`
}
