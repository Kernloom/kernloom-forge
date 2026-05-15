// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package validator_test

import (
	"path/filepath"
	"testing"

	"github.com/kernloom/kernloom-forge/internal/validator"
)

func TestDOSPreventionPolicyValid(t *testing.T) {
	reg := loadTestRegistry(t)
	path := filepath.Join(examplesDir(t), "policies", "dos-prevention.yaml")
	if err := validator.ValidatePolicyFile(path, reg); err != nil {
		t.Errorf("dos-prevention policy should be valid: %v", err)
	}
}

func TestQuarantinePolicyValid(t *testing.T) {
	reg := loadTestRegistry(t)
	path := filepath.Join(examplesDir(t), "policies", "quarantine-source.yaml")
	if err := validator.ValidatePolicyFile(path, reg); err != nil {
		t.Errorf("quarantine policy should be valid: %v", err)
	}
}

func TestPolicyWithUnknownCapabilityRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{}
	p.Kind = "RuntimePolicy"
	p.Metadata.ID = "bad-policy"
	p.Then = []validator.PolicyAction{
		{Type: "capability_action", Capability: "magic.block.everything"},
	}
	if err := validator.ValidatePolicy(p, reg); err == nil {
		t.Error("policy with unknown capability should be rejected")
	}
}

func TestPolicyWithUnknownIntentRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{}
	p.Kind = "RuntimePolicy"
	p.Metadata.ID = "bad-intent-policy"
	p.Then = []validator.PolicyAction{
		{Type: "intent_action", Intent: "magic.do.everything"},
	}
	if err := validator.ValidatePolicy(p, reg); err == nil {
		t.Error("policy with unknown intent should be rejected")
	}
}

func TestPolicyWithUnknownKindRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{}
	p.Kind = "MagicPolicy"
	p.Metadata.ID = "bad-kind"
	if err := validator.ValidatePolicy(p, reg); err == nil {
		t.Error("policy with unknown kind should be rejected")
	}
}

func TestPolicyMissingIDRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	p := &validator.Policy{Kind: "RuntimePolicy"}
	if err := validator.ValidatePolicy(p, reg); err == nil {
		t.Error("policy without id should be rejected")
	}
}
