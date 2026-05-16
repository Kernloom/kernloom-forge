// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package validator_test

import (
	"path/filepath"
	"testing"

	"github.com/kernloom/kernloom-forge/internal/validator"
)

func TestMitigateConnectionSpikePolicyValid(t *testing.T) {
	reg := loadTestRegistry(t)
	path := filepath.Join(examplesDir(t), "policies", "mitigate-connection-spike.yaml")
	if err := validator.ValidatePolicyFile(path, reg); err != nil {
		t.Errorf("mitigate-connection-spike policy should be valid: %v", err)
	}
}

func TestPolicyWithValidSignalBinding(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{
		Kind: "RuntimePolicy",
		When: validator.PolicyWhen{
			Language: "cel",
			Bindings: map[string]validator.PolicyBinding{
				"current_cps": {
					From:  "signal",
					ID:    "network.metric.connections_per_second",
					Scope: "src_ip",
				},
			},
			Expression: "vars.current_cps > 100",
		},
	}
	p.Metadata.ID = "test-signal-binding"
	if err := validator.ValidatePolicy(p, reg); err != nil {
		t.Errorf("policy with valid signal binding should pass: %v", err)
	}
}

func TestPolicyWithValidBaselineBinding(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{
		Kind: "RuntimePolicy",
		When: validator.PolicyWhen{
			Language: "cel",
			Bindings: map[string]validator.PolicyBinding{
				"upper": {
					From:      "baseline",
					Signal:    "network.metric.connections_per_second",
					Scope:     "src_ip",
					Statistic: "upper_bound",
				},
			},
			Expression: "true",
		},
	}
	p.Metadata.ID = "test-baseline-binding"
	if err := validator.ValidatePolicy(p, reg); err != nil {
		t.Errorf("policy with valid baseline binding should pass: %v", err)
	}
}

func TestPolicyUnknownSignalInBindingRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{
		Kind: "RuntimePolicy",
		When: validator.PolicyWhen{
			Language: "cel",
			Bindings: map[string]validator.PolicyBinding{
				"x": {
					From: "signal",
					ID:   "nonexistent.signal",
				},
			},
		},
	}
	p.Metadata.ID = "bad-binding"
	if err := validator.ValidatePolicy(p, reg); err == nil {
		t.Error("binding referencing unknown signal should be rejected")
	}
}

func TestPolicyUnknownBaselineStatisticRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{
		Kind: "RuntimePolicy",
		When: validator.PolicyWhen{
			Language: "cel",
			Bindings: map[string]validator.PolicyBinding{
				"bound": {
					From:      "baseline",
					Signal:    "network.metric.connections_per_second",
					Scope:     "src_ip",
					Statistic: "upper", // should be upper_bound
				},
			},
		},
	}
	p.Metadata.ID = "bad-statistic"
	if err := validator.ValidatePolicy(p, reg); err == nil {
		t.Error("binding with unknown baseline_statistic should be rejected")
	}
}

func TestPolicyInvalidBindingNameRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{
		Kind: "RuntimePolicy",
		When: validator.PolicyWhen{
			Language: "cel",
			Bindings: map[string]validator.PolicyBinding{
				"123invalid": { // starts with digit — invalid CEL identifier
					From: "signal",
					ID:   "network.metric.connections_per_second",
				},
			},
		},
	}
	p.Metadata.ID = "bad-binding-name"
	if err := validator.ValidatePolicy(p, reg); err == nil {
		t.Error("binding with invalid identifier name should be rejected")
	}
}

func TestPolicyUnknownFromValueRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{
		Kind: "RuntimePolicy",
		When: validator.PolicyWhen{
			Language: "cel",
			Bindings: map[string]validator.PolicyBinding{
				"x": {
					From: "database", // not signal or baseline
					ID:   "network.metric.connections_per_second",
				},
			},
		},
	}
	p.Metadata.ID = "bad-from"
	if err := validator.ValidatePolicy(p, reg); err == nil {
		t.Error("binding with unknown from value should be rejected")
	}
}

func TestPolicyRequirementsValidated(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{
		Kind: "RuntimePolicy",
		Requirements: validator.PolicyRequirements{
			RequiredCapabilities: []string{
				"observe.network.connection",
				"analyze.baseline.compare",
				"enforce.traffic.rate_limit",
			},
			MinGranularity: []string{"src_ip"},
		},
	}
	p.Metadata.ID = "test-requirements"
	if err := validator.ValidatePolicy(p, reg); err != nil {
		t.Errorf("policy with valid requirements should pass: %v", err)
	}
}

func TestPolicyRequirementsUnknownCapabilityRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{
		Kind: "RuntimePolicy",
		Requirements: validator.PolicyRequirements{
			RequiredCapabilities: []string{"nonexistent.capability"},
		},
	}
	p.Metadata.ID = "bad-requirements"
	if err := validator.ValidatePolicy(p, reg); err == nil {
		t.Error("policy requirements referencing unknown capability should be rejected")
	}
}

func TestPolicyBaselineRequirementsValidated(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{
		Kind: "RuntimePolicy",
		BaselineRequirements: validator.BaselineRequirements{
			Signal:          "network.metric.connections_per_second",
			PreferredScopes: []string{"src_ip", "global"},
			MinConfidence:   0.7,
			FallbackAllowed: true,
		},
	}
	p.Metadata.ID = "test-baseline-req"
	if err := validator.ValidatePolicy(p, reg); err != nil {
		t.Errorf("policy with valid baseline_requirements should pass: %v", err)
	}
}

func TestPolicyBaselineRequirementsUnknownSignalRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{
		Kind: "RuntimePolicy",
		BaselineRequirements: validator.BaselineRequirements{
			Signal: "nonexistent.metric",
		},
	}
	p.Metadata.ID = "bad-baseline-req"
	if err := validator.ValidatePolicy(p, reg); err == nil {
		t.Error("policy with unknown baseline signal should be rejected")
	}
}

func TestPolicyNewIntentRelationLearnValid(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{
		Kind:   "RuntimePolicy",
		Intent: "relation.learn",
	}
	p.Metadata.ID = "test-relation-learn"
	if err := validator.ValidatePolicy(p, reg); err != nil {
		t.Errorf("policy with relation.learn intent should be valid: %v", err)
	}
}

func TestPolicyNewIntentProtectionDosMitigateValid(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{
		Kind:   "RuntimePolicy",
		Intent: "protection.dos.mitigate",
	}
	p.Metadata.ID = "test-dos-mitigate"
	if err := validator.ValidatePolicy(p, reg); err != nil {
		t.Errorf("policy with protection.dos.mitigate intent should be valid: %v", err)
	}
}
