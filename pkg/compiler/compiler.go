// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package compiler implements the Kernloom policy compiler.
//
// Input:
//   - AccessPolicy name + RequirementSet
//   - CapabilityManifests (what each target can enforce)
//   - RequirementMappings (how to translate each requirement per target)
//
// Output — CompileReports:
//   - EnforcementCoverageReport  — coverage level per requirement per target
//   - DelegationReport           — delegated requirements with owner
//   - SemanticDowngradeReport    — precision loss per requirement per target
//   - RuntimeActionPlan          — requirements covered via Action Broker
//
// Coverage hierarchy (best → worst):
//
//	full > partial > delegated > runtime_action > pip_only > unsupported
//
// Only pip_only and unsupported count as enforcement gaps. All other coverage
// levels represent a declared, documented form of enforcement.
package compiler

import (
	"time"

	"github.com/kernloom/kernloom-forge/pkg/core/capability"
	"github.com/kernloom/kernloom-forge/pkg/core/mapping"
	"github.com/kernloom/kernloom-forge/pkg/core/report"
	"github.com/kernloom/kernloom-forge/pkg/core/requirement"
)

// TargetInput bundles a CapabilityManifest with its RequirementMapping.
// Mapping may be nil; the compiler falls back to coverage-only reporting.
type TargetInput struct {
	Manifest *capability.CapabilityManifest
	Mapping  *mapping.RequirementMapping
}

// targetResult is the internal per-target output before aggregation.
type targetResult struct {
	Coverage       report.TargetCoverage
	Delegations    []report.DelegationEntry
	Downgrades     []report.SemanticDowngradeEntry
	RuntimeActions []report.RuntimeActionEntry
}

// Compile runs the full compile pipeline for one policy against multiple targets.
// Deterministic, no side effects.
func Compile(
	policy string,
	reqs *requirement.RequirementSet,
	targets []TargetInput,
) *report.CompileReports {
	now := time.Now().UTC()

	reports := &report.CompileReports{
		Coverage: report.EnforcementCoverageReport{
			Kind:       "EnforcementCoverageReport",
			APIVersion: "kernloom.io/v1",
			PolicyName: policy,
			CompiledAt: now,
		},
		Delegation: report.DelegationReport{
			Kind:       "DelegationReport",
			APIVersion: "kernloom.io/v1",
			PolicyName: policy,
			CompiledAt: now,
		},
		Downgrade: report.SemanticDowngradeReport{
			Kind:       "SemanticDowngradeReport",
			APIVersion: "kernloom.io/v1",
			PolicyName: policy,
			CompiledAt: now,
		},
		RuntimeActions: report.RuntimeActionPlan{
			Kind:       "RuntimeActionPlan",
			APIVersion: "kernloom.io/v1",
			PolicyName: policy,
			CompiledAt: now,
		},
	}

	for _, ti := range targets {
		result := compileTarget(reqs, ti)
		reports.Coverage.Targets = append(reports.Coverage.Targets, result.Coverage)
		reports.Delegation.Delegations = append(reports.Delegation.Delegations, result.Delegations...)
		reports.Downgrade.Downgrades = append(reports.Downgrade.Downgrades, result.Downgrades...)
		reports.RuntimeActions.Entries = append(reports.RuntimeActions.Entries, result.RuntimeActions...)
	}

	return reports
}

// compileTarget produces a targetResult for one target. No side effects.
func compileTarget(reqs *requirement.RequirementSet, ti TargetInput) targetResult {
	m := ti.Manifest
	mp := ti.Mapping

	tc := report.TargetCoverage{
		TargetName:   m.Metadata.Name,
		TargetType:   string(m.Spec.TargetType),
		RuntimeOwner: m.RuntimeDecisionOwner(),
		ConfigOwner:  m.Spec.ConfigOwner,
	}

	var delegations    []report.DelegationEntry
	var downgrades     []report.SemanticDowngradeEntry
	var runtimeActions []report.RuntimeActionEntry

	downgradeSeen := map[string]bool{}
	addDowngrade := func(e report.SemanticDowngradeEntry) {
		key := e.RequirementID + "|" + e.TargetName + "|" + e.From
		if !downgradeSeen[key] {
			downgradeSeen[key] = true
			downgrades = append(downgrades, e)
		}
	}

	gapCount := 0

	for _, req := range reqs.All() {
		cov := m.CoverageFor(req.Kind)
		rr := report.RequirementResult{
			RequirementID:   req.ID,
			RequirementKind: req.Kind,
			Signal:          req.Signal,
			CEL:             req.CEL,
			Coverage:        string(cov),
		}

		if mp != nil {
			if rule := mp.RuleFor(req.Kind); rule != nil {
				rr.TargetField = rule.TargetField
				rr.Note = rule.TranslationNote
				if rule.SemanticDowngrade != nil {
					addDowngrade(report.SemanticDowngradeEntry{
						RequirementID: req.ID,
						TargetName:    m.Metadata.Name,
						From:          rule.SemanticDowngrade.From,
						To:            rule.SemanticDowngrade.To,
						Reason:        rule.SemanticDowngrade.Reason,
					})
				}
			}
		}

		switch cov {
		case capability.CoverageDelegated:
			note := ""
			if m.Spec.DelegationNotes != nil {
				note = m.Spec.DelegationNotes[req.Kind]
			}
			delMode := string(mapping.DelegationVendorRuntime)
			if mp != nil {
				if rule := mp.RuleFor(req.Kind); rule != nil && rule.DelegationMode != "" {
					delMode = string(rule.DelegationMode)
				}
			}
			delegations = append(delegations, report.DelegationEntry{
				RequirementID:   req.ID,
				RequirementKind: req.Kind,
				Signal:          req.Signal,
				DelegatedTo:     m.Metadata.Name,
				DelegationMode:  delMode,
				RuntimeOwner:    m.RuntimeDecisionOwner(),
				Note:            note,
			})

		case capability.CoveragePartial:
			for _, d := range m.Spec.Downgrades {
				if d.Requirement == req.Kind {
					addDowngrade(report.SemanticDowngradeEntry{
						RequirementID: req.ID,
						TargetName:    m.Metadata.Name,
						From:          d.From,
						To:            d.To,
						Reason:        d.Reason,
					})
				}
			}

		case capability.CoverageRuntimeAction:
			actions := make([]string, 0, len(m.Spec.RuntimeActions))
			for _, a := range m.Spec.RuntimeActions {
				actions = append(actions, a.Action)
			}
			stateOwner := ""
			if m.Spec.Ownership != nil {
				stateOwner = m.Spec.Ownership.RuntimeStateOwner
			}
			runtimeActions = append(runtimeActions, report.RuntimeActionEntry{
				RequirementID:        req.ID,
				RequirementKind:      req.Kind,
				CEL:                  req.CEL,
				TargetName:           m.Metadata.Name,
				RuntimeDecisionOwner: m.RuntimeDecisionOwner(),
				RuntimeStateOwner:    stateOwner,
				AvailableActions:     actions,
			})

		case capability.CoverageUnsupported, capability.CoveragePIPOnly:
			gapCount++
		}

		tc.Requirements = append(tc.Requirements, rr)
	}

	tc.Status = deriveStatus(len(reqs.All()), gapCount)

	return targetResult{
		Coverage:       tc,
		Delegations:    delegations,
		Downgrades:     downgrades,
		RuntimeActions: runtimeActions,
	}
}

// deriveStatus computes the TargetStatus.
// Gaps are unsupported and pip_only only — all other coverage levels are
// declared and documented forms of enforcement.
func deriveStatus(total, gaps int) report.TargetStatus {
	switch {
	case total == 0 || gaps == total:
		return report.TargetStatusNotApplicable
	case gaps > 0:
		return report.TargetStatusPartial
	default:
		return report.TargetStatusDeployable
	}
}
