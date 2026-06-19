// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package compiler implements the Kernloom policy compiler.
//
// Input:
//   - AccessPolicy          — enterprise intent (vendor-neutral)
//   - RequirementSet        — extracted canonical requirements
//   - TargetIntegrationProfile — deployment-specific integration config
//   - AdapterCapabilityManifest — product-level adapter capabilities
//   - RequirementMappingSet  — how requirements map to capabilities
//   - RuntimeActionCatalog   — available TTL-bounded actions (may be nil)
//
// Output per profile:
//   - EnforcementPlan — per-requirement enforcement status, ownership,
//     delegation notes, downgrade notes, compensating control bindings
//
// Invariants:
//   - Every requirement appears in the plan, never silently dropped.
//   - compensating_control requires an allowed action in the profile.
//   - delegated requires a delegation spec in the mapping.
//   - partial requires a downgrade note in the mapping.
//   - An unsupported requirement makes the plan non-deployable.
package compiler

import (
	"time"

	"github.com/kernloom/kernloom-forge/pkg/core/action"
	"github.com/kernloom/kernloom-forge/pkg/core/adapter"
	"github.com/kernloom/kernloom-forge/pkg/core/mapping"
	"github.com/kernloom/kernloom-forge/pkg/core/plan"
	"github.com/kernloom/kernloom-forge/pkg/core/profile"
	"github.com/kernloom/kernloom-forge/pkg/core/requirement"
)

// TargetBundle groups the four adapter-level artifacts for one target.
// The Catalog may be nil when no runtime actions are needed (config_only).
type TargetBundle struct {
	Adapter  *adapter.AdapterCapabilityManifest
	Mappings *mapping.RequirementMappingSet
	Catalog  *action.RuntimeActionCatalog // may be nil
}

// Compile produces one EnforcementPlan per profile by matching the
// RequirementSet against each profile's associated TargetBundle.
//
// bundles maps adapterRef (= profile.Spec.AdapterRef) to the loaded artifacts.
func Compile(
	policyName string,
	reqs *requirement.RequirementSet,
	profiles []*profile.TargetIntegrationProfile,
	bundles map[string]*TargetBundle,
) []*plan.EnforcementPlan {
	now := time.Now().UTC()
	var plans []*plan.EnforcementPlan

	for _, prof := range profiles {
		bundle := bundles[prof.Spec.AdapterRef]
		p := compileOne(policyName, now, reqs, prof, bundle)
		plans = append(plans, p)
	}

	return plans
}

// compileOne produces one EnforcementPlan for a single profile.
func compileOne(
	policyName string,
	now time.Time,
	reqs *requirement.RequirementSet,
	prof *profile.TargetIntegrationProfile,
	bundle *TargetBundle,
) *plan.EnforcementPlan {
	ep := &plan.EnforcementPlan{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "EnforcementPlan",
		Metadata: plan.PlanMetadata{
			Name:         policyName + "-" + prof.Metadata.Name,
			SourcePolicy: policyName,
			Target:       prof.Metadata.Name,
			CompiledAt:   now,
		},
	}

	var unsupported, delegated, compensating, downgrades []string

	for _, req := range reqs.All() {
		entry := compileRequirement(req, prof, bundle)
		ep.Spec.Requirements = append(ep.Spec.Requirements, entry)

		switch entry.Status {
		case plan.StatusUnsupported:
			unsupported = append(unsupported, req.ID)
		case plan.StatusDelegated:
			delegated = append(delegated, req.ID)
		case plan.StatusCompensatingControl:
			compensating = append(compensating, req.ID)
		case plan.StatusPartial:
			downgrades = append(downgrades, req.ID)
		}
	}

	ep.Spec.Summary = plan.PlanSummary{
		Deployable:           len(unsupported) == 0,
		RuntimeModel:         string(prof.Spec.Mode),
		SemanticFidelity:     aggregateFidelity(ep.Spec.Requirements),
		Delegation:           delegated,
		CompensatingControls: compensating,
		Downgrades:           downgrades,
		Unsupported:          unsupported,
	}

	return ep
}

// compileRequirement determines the enforcement status for one requirement.
func compileRequirement(
	req requirement.Requirement,
	prof *profile.TargetIntegrationProfile,
	bundle *TargetBundle,
) plan.RequirementEnforcement {
	entry := plan.RequirementEnforcement{
		ID:              req.ID,
		RequirementKind: req.Kind,
		Requirement:     req.CEL,
	}

	// No bundle → everything is unsupported.
	if bundle == nil || bundle.Mappings == nil {
		entry.Status = plan.StatusUnsupported
		return entry
	}

	mappingEntry := bundle.Mappings.ForKind(req.Kind)
	if mappingEntry == nil {
		entry.Status = plan.StatusUnsupported
		return entry
	}

	entry.Capability = mappingEntry.Capability.ID
	entry.Fidelity = string(mappingEntry.Fidelity)

	switch mappingEntry.Support {
	case mapping.SupportFull:
		entry.Status = plan.StatusImplemented

	case mapping.SupportPartial:
		entry.Status = plan.StatusPartial
		if mappingEntry.Downgrade != nil {
			entry.Downgrade = &plan.DowngradeNote{
				From:   mappingEntry.Downgrade.From,
				To:     mappingEntry.Downgrade.To,
				Reason: mappingEntry.Downgrade.Reason,
			}
		}

	case mapping.SupportDelegated:
		entry.Status = plan.StatusDelegated
		if mappingEntry.Delegation != nil {
			entry.Delegation = &plan.DelegationNote{
				EvaluationOwner: mappingEntry.Delegation.EvaluationOwner,
				Note:            mappingEntry.Delegation.Note,
			}
			entry.Ownership = &plan.RequirementOwnership{
				TargetAuthorizationOwner: mappingEntry.Delegation.EvaluationOwner,
				PolicyEvaluationOwner:    mappingEntry.Delegation.EvaluationOwner,
				EnforcementOwner:         prof.Spec.Ownership.Enforcement.Owner,
			}
		}

	case mapping.SupportCompensatingControl:
		b := mappingEntry.Binding
		if b == nil {
			entry.Status = plan.StatusUnsupported
			return entry
		}
		// Validate the action is allowed in this profile.
		if !prof.IsActionAllowed(b.Action) {
			entry.Status = plan.StatusUnsupported
			return entry
		}
		// Validate the action exists in the catalog.
		if bundle.Catalog == nil || bundle.Catalog.ActionByID(b.Action) == nil {
			entry.Status = plan.StatusUnsupported
			return entry
		}
		entry.Status = plan.StatusCompensatingControl
		entry.ActionBinding = &plan.ActionBinding{
			Action:        b.Action,
			Attribute:     b.Attribute,
			DecisionOwner: b.DecisionOwner,
		}
		entry.Ownership = &plan.RequirementOwnership{
			RiskAssessmentOwner:      b.RiskAssessmentOwner,
			EnterpriseDecisionOwner:  b.DecisionOwner,
			TargetAuthorizationOwner: prof.Spec.Ownership.TargetAuthorizationDecision.Owner,
			PolicyEvaluationOwner:    prof.Spec.Ownership.TargetPolicyEvaluation.Owner,
			EnforcementOwner:         prof.Spec.Ownership.Enforcement.Owner,
		}

	case mapping.SupportUnsupported:
		entry.Status = plan.StatusUnsupported
	}

	return entry
}

// aggregateFidelity returns the lowest fidelity across all mapped requirements.
// Unsupported requirements are excluded from the fidelity calculation.
func aggregateFidelity(reqs []plan.RequirementEnforcement) string {
	lowest := "high"
	order := map[string]int{"high": 3, "medium": 2, "low": 1, "": 0}
	for _, r := range reqs {
		if r.Status == plan.StatusUnsupported {
			continue
		}
		if r.Fidelity == "" {
			continue
		}
		if order[r.Fidelity] < order[lowest] {
			lowest = r.Fidelity
		}
	}
	if lowest == "high" && allUnsupported(reqs) {
		return "none"
	}
	return lowest
}

func allUnsupported(reqs []plan.RequirementEnforcement) bool {
	for _, r := range reqs {
		if r.Status != plan.StatusUnsupported {
			return false
		}
	}
	return true
}
