// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"errors"
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom-forge/pkg/bundler"
	"github.com/kernloom/kernloom-forge/pkg/core/plan"
	"github.com/kernloom/kernloom-forge/pkg/core/profile"
)

func TestSelectAutoPlacementMatchesReportedAdapterAndCapabilities(t *testing.T) {
	node := testNodeRecord(t, []string{"enforce.traffic.rate_limit"}, nil)
	placement, err := selectAutoPlacement(
		node,
		[]*plan.EnforcementPlan{testPlacementPlan("klshield-local", true)},
		[]*profile.TargetIntegrationProfile{testPlacementProfile("klshield-local", "klshield")},
		bundler.RuntimePolicyConfig{
			NodeID:         node.NodeID,
			Generation:     1,
			DetectionRules: testPlacementDetections(),
			ResponseRules:  testPlacementResponses("enforce.traffic.rate_limit"),
		},
	)
	if err != nil {
		t.Fatalf("selectAutoPlacement: %v", err)
	}
	if placement.Plan.Metadata.Target != "klshield-local" {
		t.Fatalf("target = %q", placement.Plan.Metadata.Target)
	}
	if len(placement.Pack.Spec.CapabilitiesRequired) != 1 || placement.Pack.Spec.CapabilitiesRequired[0] != "enforce.traffic.rate_limit" {
		t.Fatalf("capabilities = %#v", placement.Pack.Spec.CapabilitiesRequired)
	}
}

func TestSelectAutoPlacementRejectsMissingCapabilities(t *testing.T) {
	node := testNodeRecord(t, []string{"enforce.access.deny"}, nil)
	_, err := selectAutoPlacement(
		node,
		[]*plan.EnforcementPlan{testPlacementPlan("klshield-local", true)},
		[]*profile.TargetIntegrationProfile{testPlacementProfile("klshield-local", "klshield")},
		bundler.RuntimePolicyConfig{
			NodeID:         node.NodeID,
			Generation:     1,
			DetectionRules: testPlacementDetections(),
			ResponseRules:  testPlacementResponses("enforce.traffic.rate_limit"),
		},
	)
	if !errors.Is(err, errNoPolicyAssignment) {
		t.Fatalf("expected no placement, got %v", err)
	}
}

func testPlacementPlan(target string, deployable bool) *plan.EnforcementPlan {
	return &plan.EnforcementPlan{
		Metadata: plan.PlanMetadata{
			Name:         "manual-edge-" + target,
			SourcePolicy: "manual-edge",
			Target:       target,
			CompiledAt:   time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC),
		},
		Spec: plan.EnforcementPlanSpec{
			Summary: plan.PlanSummary{
				Deployable:       deployable,
				RuntimeModel:     "kernloom_pdp_native",
				SemanticFidelity: "exact",
			},
		},
	}
}

func testPlacementProfile(name, adapter string) *profile.TargetIntegrationProfile {
	return &profile.TargetIntegrationProfile{
		Metadata: profile.ProfileMetadata{Name: name},
		Spec: profile.ProfileSpec{
			AdapterRef:            adapter,
			AllowedRuntimeActions: []string{"network.rate_limit_source"},
		},
	}
}

func testPlacementDetections() []contracts.RuntimeDetectionRule {
	return []contracts.RuntimeDetectionRule{{
		ID:        "risk-high",
		Type:      "metric.threshold",
		Threshold: 1,
		Params: map[string]any{
			"key":      "subject.risk.level",
			"operator": "eq",
			"value":    "high",
		},
	}}
}

func testPlacementResponses(action string) []contracts.RuntimeResponseRule {
	return []contracts.RuntimeResponseRule{{
		ID: "rate-limit-risk",
		When: contracts.RuntimeResponseTrigger{
			Detection: "risk-high",
		},
		Then: []contracts.RuntimeResponseAction{{
			ID:  action,
			TTL: contracts.NewDuration(5 * time.Minute),
			Target: contracts.RuntimeResponseTarget{
				Scope: "source",
			},
		}},
	}}
}
