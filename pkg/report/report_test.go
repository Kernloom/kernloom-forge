// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package report_test

import (
	"testing"

	"github.com/kernloom/kernloom-forge/pkg/core/plan"
	"github.com/kernloom/kernloom-forge/pkg/report"
)

func TestBuildReportSet(t *testing.T) {
	rs := report.Build("policy", []*plan.EnforcementPlan{{
		Metadata: plan.PlanMetadata{Target: "target"},
		Spec: plan.EnforcementPlanSpec{
			Requirements: []plan.RequirementEnforcement{
				{ID: "implemented", Status: plan.StatusImplemented},
				{ID: "delegated", Status: plan.StatusDelegated, Delegation: &plan.DelegationNote{EvaluationOwner: "vendor"}},
				{ID: "downgraded", Status: plan.StatusPartial, Downgrade: &plan.DowngradeNote{From: "a", To: "b", Reason: "test"}},
				{ID: "context-sensitive", Status: plan.StatusCompensatingControl, RuntimeNotes: []string{"missing context is not a deny trigger"}},
			},
			Summary: plan.PlanSummary{
				Deployable:       true,
				RuntimeModel:     "config_only",
				SemanticFidelity: "medium",
				Delegation:       []string{"delegated"},
				Downgrades:       []string{"downgraded"},
			},
		},
	}}, nil)
	if len(rs.Spec.Coverage) != 1 || len(rs.Spec.Delegation) != 1 || len(rs.Spec.Downgrades) != 1 {
		t.Fatalf("unexpected report set: %#v", rs.Spec)
	}
	if len(rs.Spec.RuntimeNotes) != 1 || rs.Spec.RuntimeNotes[0].Requirement != "context-sensitive" {
		t.Fatalf("runtime notes were not surfaced: %#v", rs.Spec.RuntimeNotes)
	}
}
