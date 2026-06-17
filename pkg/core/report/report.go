// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package report defines the transparency reports every compile run produces.
//
//   - EnforcementCoverageReport  — what is enforced where, and at what level.
//   - DelegationReport           — what is delegated to vendor PDPs, with owner.
//   - SemanticDowngradeReport    — where precision is lost in translation.
//   - RuntimeActionPlan          — which requirements are covered via Kernloom
//     runtime actions, and which actions the target adapter supports.
//
// Missing requirements must never disappear silently — they appear in one of
// these reports. A policy that compiles without reports is not valid output.
package report

import (
	"fmt"
	"time"
)

// TargetStatus summarises the overall enforcement posture for one target.
type TargetStatus string

const (
	// TargetStatusDeployable means all requirements are either fully enforced,
	// explicitly delegated, covered via runtime actions, or semantically
	// downgraded — all with documented justification.
	TargetStatusDeployable TargetStatus = "deployable"

	// TargetStatusPartial means some requirements cannot be covered by this
	// target in any declared form (unsupported or pip_only).
	TargetStatusPartial TargetStatus = "partial"

	// TargetStatusNotApplicable means this target cannot handle any of the
	// requirements in the policy.
	TargetStatusNotApplicable TargetStatus = "not_applicable"
)

// RequirementResult is one row in a coverage report: the outcome for a single
// requirement on a single target.
type RequirementResult struct {
	RequirementID   string `yaml:"requirement_id"`
	RequirementKind string `yaml:"requirement_kind"`
	Signal          string `yaml:"signal,omitempty"`
	CEL             string `yaml:"cel,omitempty"`
	Coverage        string `yaml:"coverage"` // full|partial|delegated|runtime_action|unsupported|pip_only
	TargetField     string `yaml:"target_field,omitempty"`
	Note            string `yaml:"note,omitempty"`
}

// TargetCoverage aggregates all requirement results for one target.
type TargetCoverage struct {
	TargetName   string              `yaml:"target_name"`
	TargetType   string              `yaml:"target_type"`
	RuntimeOwner string              `yaml:"runtime_owner"`
	ConfigOwner  string              `yaml:"config_owner"`
	Status       TargetStatus        `yaml:"status"`
	Requirements []RequirementResult `yaml:"requirements"`
}

// FullCount returns the number of fully covered requirements.
func (tc *TargetCoverage) FullCount() int {
	n := 0
	for _, r := range tc.Requirements {
		if r.Coverage == "full" {
			n++
		}
	}
	return n
}

// GapCount returns the number of requirements that are unsupported or pip_only.
func (tc *TargetCoverage) GapCount() int {
	n := 0
	for _, r := range tc.Requirements {
		if r.Coverage == "unsupported" || r.Coverage == "pip_only" {
			n++
		}
	}
	return n
}

// EnforcementCoverageReport describes how well each target enforces the policy.
type EnforcementCoverageReport struct {
	Kind       string           `yaml:"kind"`
	APIVersion string           `yaml:"apiVersion"`
	PolicyName string           `yaml:"policy_name"`
	CompiledAt time.Time        `yaml:"compiled_at"`
	Targets    []TargetCoverage `yaml:"targets"`
}

// TargetFor returns the TargetCoverage for a named target, or nil.
func (r *EnforcementCoverageReport) TargetFor(name string) *TargetCoverage {
	for i := range r.Targets {
		if r.Targets[i].TargetName == name {
			return &r.Targets[i]
		}
	}
	return nil
}

// DelegationEntry documents one delegated requirement on one target.
type DelegationEntry struct {
	RequirementID   string `yaml:"requirement_id"`
	RequirementKind string `yaml:"requirement_kind"`
	Signal          string `yaml:"signal,omitempty"`
	DelegatedTo     string `yaml:"delegated_to"`
	DelegationMode  string `yaml:"delegation_mode"`
	RuntimeOwner    string `yaml:"runtime_owner"`
	Note            string `yaml:"note,omitempty"`
}

// DelegationReport lists every requirement delegated to a vendor or external system.
type DelegationReport struct {
	Kind        string            `yaml:"kind"`
	APIVersion  string            `yaml:"apiVersion"`
	PolicyName  string            `yaml:"policy_name"`
	CompiledAt  time.Time         `yaml:"compiled_at"`
	Delegations []DelegationEntry `yaml:"delegations"`
}

// SemanticDowngradeEntry documents one instance of precision loss.
type SemanticDowngradeEntry struct {
	RequirementID string `yaml:"requirement_id"`
	TargetName    string `yaml:"target_name"`
	From          string `yaml:"from"`
	To            string `yaml:"to"`
	Reason        string `yaml:"reason"`
}

// SemanticDowngradeReport lists every case where a requirement is representable
// but with reduced semantic fidelity.
type SemanticDowngradeReport struct {
	Kind       string                   `yaml:"kind"`
	APIVersion string                   `yaml:"apiVersion"`
	PolicyName string                   `yaml:"policy_name"`
	CompiledAt time.Time                `yaml:"compiled_at"`
	Downgrades []SemanticDowngradeEntry `yaml:"downgrades"`
}

// RuntimeActionEntry describes one requirement that is covered via Kernloom
// runtime actions on a specific target.
type RuntimeActionEntry struct {
	// RequirementID and Kind identify the requirement being enforced.
	RequirementID   string `yaml:"requirement_id"`
	RequirementKind string `yaml:"requirement_kind"`

	// CEL is the condition expression. The action fires when this evaluates
	// to false (the requirement is not met at runtime).
	CEL string `yaml:"cel,omitempty"`

	// TargetName is the target whose action adapter is invoked.
	TargetName string `yaml:"target_name"`

	// RuntimeDecisionOwner is the PDP that evaluates the condition and
	// triggers the action — typically "kernloom-runtime-pdp".
	RuntimeDecisionOwner string `yaml:"runtime_decision_owner"`

	// RuntimeStateOwner holds the state that the action modifies.
	RuntimeStateOwner string `yaml:"runtime_state_owner,omitempty"`

	// AvailableActions lists the adapter actions that can enforce this
	// requirement. The Action Broker selects based on context and policy.
	AvailableActions []string `yaml:"available_actions"`
}

// RuntimeActionPlan lists all requirements covered by Kernloom runtime actions
// across all targets. This plan is consumed by the Action Broker to know which
// actions to invoke when the runtime PDP makes a deny/restrict decision.
type RuntimeActionPlan struct {
	Kind       string               `yaml:"kind"`
	APIVersion string               `yaml:"apiVersion"`
	PolicyName string               `yaml:"policy_name"`
	CompiledAt time.Time            `yaml:"compiled_at"`
	Entries    []RuntimeActionEntry `yaml:"entries"`
}

// CompileReports bundles all reports produced for one policy compile run.
type CompileReports struct {
	Coverage       EnforcementCoverageReport
	Delegation     DelegationReport
	Downgrade      SemanticDowngradeReport
	RuntimeActions RuntimeActionPlan
}

// Summary returns a human-readable per-target status overview.
func (cr *CompileReports) Summary() string {
	out := fmt.Sprintf("Policy: %s\n", cr.Coverage.PolicyName)
	for _, t := range cr.Coverage.Targets {
		out += fmt.Sprintf("  %-24s status=%-18s full=%d gaps=%d\n",
			t.TargetName, t.Status, t.FullCount(), t.GapCount())
	}
	if len(cr.Delegation.Delegations) > 0 {
		out += fmt.Sprintf("  Delegations:         %d\n", len(cr.Delegation.Delegations))
	}
	if len(cr.Downgrade.Downgrades) > 0 {
		out += fmt.Sprintf("  Semantic downgrades: %d\n", len(cr.Downgrade.Downgrades))
	}
	if len(cr.RuntimeActions.Entries) > 0 {
		out += fmt.Sprintf("  Runtime action plan: %d requirement(s) via Action Broker\n",
			len(cr.RuntimeActions.Entries))
	}
	return out
}
