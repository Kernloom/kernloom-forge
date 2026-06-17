// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package plan defines the EnforcementPlan — the compiler's output for one
// policy compiled against one TargetIntegrationProfile.
//
// An EnforcementPlan is generated, not authored. It answers per requirement:
//   - What is the enforcement status?
//   - Which adapter capability handles it?
//   - Who owns each enforcement concern for this requirement?
//   - Is precision lost? How?
//   - Is a compensating control binding to an action?
//
// The summary section provides the overall deployability verdict, the
// runtime model in use, and the aggregate fidelity level.
package plan

import "time"

// RequirementStatus describes the enforcement outcome for a single requirement.
type RequirementStatus string

const (
	// StatusImplemented: the adapter can fully and natively enforce this
	// requirement with high semantic fidelity.
	StatusImplemented RequirementStatus = "implemented"

	// StatusDelegated: the vendor's own PDP evaluates a semantically
	// equivalent condition natively at runtime.
	StatusDelegated RequirementStatus = "delegated"

	// StatusCompensatingControl: the adapter cannot evaluate the requirement
	// natively; Kernloom compensates via a TTL-bounded restrictive runtime
	// action that takes effect when the condition is violated.
	StatusCompensatingControl RequirementStatus = "compensating_control"

	// StatusPartial: the adapter approximates the requirement but with reduced
	// semantic fidelity. A DowngradeNote documents the precision loss.
	StatusPartial RequirementStatus = "partial"

	// StatusUnsupported: no available mapping; requirement cannot be satisfied
	// by this target in any declared form.
	StatusUnsupported RequirementStatus = "unsupported"
)

// EnforcementPlan is the top-level compiler output for one policy+profile pair.
type EnforcementPlan struct {
	APIVersion string              `yaml:"apiVersion"`
	Kind       string              `yaml:"kind"`
	Metadata   PlanMetadata        `yaml:"metadata"`
	Spec       EnforcementPlanSpec `yaml:"spec"`
}

// PlanMetadata identifies the enforcement plan.
type PlanMetadata struct {
	Name         string    `yaml:"name"`
	SourcePolicy string    `yaml:"sourcePolicy"`
	Target       string    `yaml:"target"` // TargetIntegrationProfile name
	CompiledAt   time.Time `yaml:"compiledAt"`
}

// EnforcementPlanSpec is the normative body of an EnforcementPlan.
type EnforcementPlanSpec struct {
	Requirements []RequirementEnforcement `yaml:"requirements"`
	Summary      PlanSummary              `yaml:"summary"`
}

// RequirementEnforcement describes the enforcement outcome for one requirement.
type RequirementEnforcement struct {
	// ID is the requirement identifier from the AccessPolicy condition.
	ID string `yaml:"id"`

	// Requirement is the CEL expression of the condition.
	Requirement string `yaml:"requirement,omitempty"`

	// Status is the enforcement outcome.
	Status RequirementStatus `yaml:"status"`

	// Capability is the adapter capability ID that handles this requirement.
	// Absent for compensating_control and unsupported.
	Capability string `yaml:"capability,omitempty"`

	// Fidelity is the semantic precision of the mapping.
	Fidelity string `yaml:"fidelity,omitempty"`

	// Ownership declares per-requirement concern ownership.
	// Set for delegated and compensating_control requirements where ownership
	// differs from the profile default.
	Ownership *RequirementOwnership `yaml:"ownership,omitempty"`

	// Delegation documents the delegation when status is delegated.
	Delegation *DelegationNote `yaml:"delegation,omitempty"`

	// Downgrade documents the precision loss when status is partial.
	Downgrade *DowngradeNote `yaml:"downgrade,omitempty"`

	// ActionBinding describes the compensating control binding.
	// Set only when status is compensating_control.
	ActionBinding *ActionBinding `yaml:"actionBinding,omitempty"`
}

// RequirementOwnership maps each enforcement concern to its named owner
// for a specific requirement. Used when a requirement's ownership differs
// from the profile's default (e.g. a delegated requirement where the vendor
// owns the runtime decision but Kernloom owns the risk assessment).
type RequirementOwnership struct {
	RiskAssessmentOwner       string `yaml:"riskAssessmentOwner,omitempty"`
	EnterpriseDecisionOwner   string `yaml:"enterpriseDecisionOwner,omitempty"`
	TargetAuthorizationOwner  string `yaml:"targetAuthorizationOwner,omitempty"`
	PolicyEvaluationOwner     string `yaml:"policyEvaluationOwner,omitempty"`
	EnforcementOwner          string `yaml:"enforcementOwner,omitempty"`
}

// DelegationNote documents a delegated requirement.
type DelegationNote struct {
	EvaluationOwner string `yaml:"evaluationOwner"`
	Note            string `yaml:"note,omitempty"`
}

// DowngradeNote documents precision loss in a partial mapping.
type DowngradeNote struct {
	From   string `yaml:"from"`
	To     string `yaml:"to"`
	Reason string `yaml:"reason"`
}

// ActionBinding describes the compensating action that enforces a requirement
// when the vendor cannot evaluate it natively.
type ActionBinding struct {
	// Action is the action ID from the RuntimeActionCatalog.
	Action string `yaml:"action"`

	// Attribute is the vendor-specific parameter for the action.
	// For OpenZiti: "kl.access.active" (the role attribute to remove).
	Attribute string `yaml:"attribute,omitempty"`

	// MaxTTL is the maximum duration for the TTL-bounded restriction.
	MaxTTL string `yaml:"maxTTL,omitempty"`

	// DecisionOwner is the component that triggers the action.
	DecisionOwner string `yaml:"decisionOwner,omitempty"`
}

// PlanSummary provides the overall verdict and aggregate metrics.
type PlanSummary struct {
	// Deployable is true when all requirements are accounted for:
	// implemented, delegated, compensating_control, or partial.
	// False when any requirement is unsupported.
	Deployable bool `yaml:"deployable"`

	// RuntimeModel is the integration mode from the TargetIntegrationProfile.
	RuntimeModel string `yaml:"runtimeModel"`

	// SemanticFidelity is the lowest fidelity across all mapped requirements.
	SemanticFidelity string `yaml:"semanticFidelity"`

	// Delegation lists requirement IDs that are delegated to the vendor PDP.
	Delegation []string `yaml:"delegation,omitempty"`

	// CompensatingControls lists requirement IDs handled via runtime actions.
	CompensatingControls []string `yaml:"compensatingControls,omitempty"`

	// Downgrades lists requirement IDs with partial semantic fidelity.
	Downgrades []string `yaml:"downgrades,omitempty"`

	// Unsupported lists requirement IDs that cannot be satisfied.
	// A non-empty list means Deployable is false.
	Unsupported []string `yaml:"unsupported,omitempty"`
}

// Summary returns a human-readable one-line status.
func (p *EnforcementPlan) Summary() string {
	s := p.Spec.Summary
	status := "deployable"
	if !s.Deployable {
		status = "NOT deployable"
	}
	result := p.Metadata.SourcePolicy + " → " + p.Metadata.Target +
		"  [" + status + "]  fidelity=" + s.SemanticFidelity +
		"  model=" + s.RuntimeModel
	if len(s.Unsupported) > 0 {
		result += "  unsupported=" + join(s.Unsupported)
	}
	if len(s.CompensatingControls) > 0 {
		result += "  compensating=" + join(s.CompensatingControls)
	}
	if len(s.Delegation) > 0 {
		result += "  delegated=" + join(s.Delegation)
	}
	if len(s.Downgrades) > 0 {
		result += "  downgraded=" + join(s.Downgrades)
	}
	return result
}

func join(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	out := "["
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out + "]"
}
