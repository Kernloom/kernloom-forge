// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package configpdp validates compiled plans before durable deployment.
package configpdp

import (
	"fmt"
	"time"

	"github.com/kernloom/kernloom-forge/pkg/core/intent"
	"github.com/kernloom/kernloom-forge/pkg/core/plan"
)

const (
	ResultAllow            = "allow"
	ResultAllowWithWarning = "allow_with_warnings"
	ResultDeny             = "deny"
)

type ValidationReport struct {
	APIVersion string                   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string                   `yaml:"kind" json:"kind"`
	Metadata   ValidationReportMetadata `yaml:"metadata" json:"metadata"`
	Spec       ValidationReportSpec     `yaml:"spec" json:"spec"`
}

type ValidationReportMetadata struct {
	SourcePolicy string    `yaml:"sourcePolicy" json:"sourcePolicy"`
	Target       string    `yaml:"target" json:"target"`
	ValidatedAt  time.Time `yaml:"validatedAt" json:"validatedAt"`
}

type ValidationReportSpec struct {
	Result   string  `yaml:"result" json:"result"`
	Checks   []Check `yaml:"checks" json:"checks"`
	Warnings []Issue `yaml:"warnings,omitempty" json:"warnings,omitempty"`
	Failures []Issue `yaml:"failures,omitempty" json:"failures,omitempty"`
}

type Check struct {
	Name   string `yaml:"name" json:"name"`
	Result string `yaml:"result" json:"result"`
	Detail string `yaml:"detail,omitempty" json:"detail,omitempty"`
}

type Issue struct {
	Requirement string `yaml:"requirement,omitempty" json:"requirement,omitempty"`
	Message     string `yaml:"message" json:"message"`
}

func Validate(policy *intent.AccessPolicy, ep *plan.EnforcementPlan) ValidationReport {
	now := time.Now().UTC()
	report := ValidationReport{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "ConfigPDPValidationReport",
		Metadata: ValidationReportMetadata{
			ValidatedAt: now,
		},
	}
	if policy != nil {
		report.Metadata.SourcePolicy = policy.Metadata.Name
	}
	if ep != nil {
		report.Metadata.Target = ep.Metadata.Target
	}
	if policy == nil {
		return deny(report, "policy_present", Issue{Message: "policy is required"})
	}
	if ep == nil {
		return deny(report, "enforcement_plan_present", Issue{Message: "enforcement plan is required"})
	}

	c := policy.Spec.EnforcementConstraints
	pass(&report, "policy_present", "policy loaded")
	pass(&report, "enforcement_plan_present", "plan loaded")

	for _, req := range ep.Spec.Requirements {
		switch req.Status {
		case plan.StatusUnsupported:
			fail(&report, "unsupported_requirement", Issue{
				Requirement: req.ID,
				Message:     "requirement is unsupported by target",
			})

		case plan.StatusDelegated:
			if c != nil && c.AllowDelegation != nil && !*c.AllowDelegation {
				fail(&report, "delegation_allowed", Issue{Requirement: req.ID, Message: "delegation is not allowed by policy"})
			}
			if c != nil && len(c.AllowedDelegationOwners) > 0 {
				owner := ""
				if req.Delegation != nil {
					owner = req.Delegation.EvaluationOwner
				}
				if !contains(c.AllowedDelegationOwners, owner) {
					fail(&report, "delegation_owner_allowed", Issue{Requirement: req.ID, Message: fmt.Sprintf("delegation owner %q is not allowed", owner)})
				}
			}

		case plan.StatusPartial:
			if c != nil && c.AllowSemanticDowngrade != nil && !*c.AllowSemanticDowngrade {
				fail(&report, "semantic_downgrade_allowed", Issue{Requirement: req.ID, Message: "semantic downgrade is not allowed by policy"})
			}

		case plan.StatusCompensatingControl:
			if c != nil && len(c.AllowedRuntimeActions) > 0 {
				action := ""
				if req.ActionBinding != nil {
					action = req.ActionBinding.Action
				}
				if !contains(c.AllowedRuntimeActions, action) {
					fail(&report, "runtime_action_allowed", Issue{Requirement: req.ID, Message: fmt.Sprintf("runtime action %q is not allowed", action)})
				}
			}
		}
	}

	if c != nil && c.MinimumFidelity != "" && fidelityRank(ep.Spec.Summary.SemanticFidelity) < fidelityRank(c.MinimumFidelity) {
		fail(&report, "minimum_fidelity", Issue{
			Message: fmt.Sprintf("plan fidelity %q is below policy minimum %q", ep.Spec.Summary.SemanticFidelity, c.MinimumFidelity),
		})
	}
	if c != nil {
		for _, gate := range c.RequireApprovalFor {
			switch gate {
			case "semantic_downgrade":
				if len(ep.Spec.Summary.Downgrades) > 0 {
					warn(&report, Issue{Message: "semantic downgrade requires external approval"})
				}
			case "runtime_delegation", "vendor_native_semantics":
				if len(ep.Spec.Summary.Delegation) > 0 {
					warn(&report, Issue{Message: "runtime delegation requires external approval"})
				}
			case "runtime_action", "near_runtime_action":
				if len(ep.Spec.Summary.CompensatingControls) > 0 {
					warn(&report, Issue{Message: "runtime action requires external approval"})
				}
			}
		}
	}

	if len(report.Spec.Failures) > 0 {
		report.Spec.Result = ResultDeny
	} else if len(report.Spec.Warnings) > 0 {
		report.Spec.Result = ResultAllowWithWarning
	} else {
		report.Spec.Result = ResultAllow
	}
	return report
}

func deny(report ValidationReport, check string, issue Issue) ValidationReport {
	fail(&report, check, issue)
	report.Spec.Result = ResultDeny
	return report
}

func pass(report *ValidationReport, name, detail string) {
	report.Spec.Checks = append(report.Spec.Checks, Check{Name: name, Result: "pass", Detail: detail})
}

func fail(report *ValidationReport, check string, issue Issue) {
	report.Spec.Checks = append(report.Spec.Checks, Check{Name: check, Result: "fail", Detail: issue.Message})
	report.Spec.Failures = append(report.Spec.Failures, issue)
}

func warn(report *ValidationReport, issue Issue) {
	report.Spec.Warnings = append(report.Spec.Warnings, issue)
}

func contains(values []string, needle string) bool {
	for _, v := range values {
		if v == needle {
			return true
		}
	}
	return false
}

func fidelityRank(v string) int {
	switch v {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
