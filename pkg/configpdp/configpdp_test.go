// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package configpdp_test

import (
	"testing"

	"github.com/kernloom/kernloom-forge/pkg/configpdp"
	"github.com/kernloom/kernloom-forge/pkg/core/intent"
	"github.com/kernloom/kernloom-forge/pkg/core/plan"
)

func TestValidateAllowsCleanPlan(t *testing.T) {
	r := configpdp.Validate(testPolicy(nil), testPlan(plan.StatusImplemented))
	if r.Spec.Result != configpdp.ResultAllow {
		t.Fatalf("result = %s failures=%v", r.Spec.Result, r.Spec.Failures)
	}
}

func TestValidateRejectsUnsupportedRequirement(t *testing.T) {
	r := configpdp.Validate(testPolicy(nil), testPlan(plan.StatusUnsupported))
	if r.Spec.Result != configpdp.ResultDeny {
		t.Fatalf("result = %s, want deny", r.Spec.Result)
	}
}

func TestValidateRejectsDisallowedDowngrade(t *testing.T) {
	no := false
	r := configpdp.Validate(testPolicy(&intent.EnforcementConstraints{
		AllowSemanticDowngrade: &no,
	}), testPlan(plan.StatusPartial))
	if r.Spec.Result != configpdp.ResultDeny {
		t.Fatalf("result = %s, want deny", r.Spec.Result)
	}
}

func TestValidateRejectsUnapprovedRuntimeAction(t *testing.T) {
	r := configpdp.Validate(testPolicy(&intent.EnforcementConstraints{
		AllowedRuntimeActions: []string{"network.flow_rate_limit"},
	}), testPlan(plan.StatusCompensatingControl))
	if r.Spec.Result != configpdp.ResultDeny {
		t.Fatalf("result = %s, want deny", r.Spec.Result)
	}
}

func testPolicy(c *intent.EnforcementConstraints) *intent.AccessPolicy {
	return &intent.AccessPolicy{
		APIVersion: "kernloom.io/v1",
		Kind:       intent.KindAccessPolicy,
		Metadata:   intent.PolicyMetadata{Name: "policy"},
		Spec: intent.AccessPolicySpec{
			Subject:                intent.Subject{Type: "role", Ref: "users"},
			Action:                 "access",
			Resource:               intent.Resource{Type: "service", Ref: "app"},
			Effect:                 "allow",
			EnforcementConstraints: c,
		},
	}
}

func testPlan(status plan.RequirementStatus) *plan.EnforcementPlan {
	req := plan.RequirementEnforcement{
		ID:              "require-low-risk",
		RequirementKind: "risk_level",
		Status:          status,
		Fidelity:        "low",
	}
	if status == plan.StatusCompensatingControl {
		req.ActionBinding = &plan.ActionBinding{Action: "network.flow_deny"}
	}
	return &plan.EnforcementPlan{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "EnforcementPlan",
		Metadata:   plan.PlanMetadata{SourcePolicy: "policy", Target: "target"},
		Spec: plan.EnforcementPlanSpec{
			Requirements: []plan.RequirementEnforcement{req},
			Summary:      plan.PlanSummary{Deployable: status != plan.StatusUnsupported, SemanticFidelity: "low"},
		},
	}
}
