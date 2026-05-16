// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package packs_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kernloom/kernloom-forge/internal/packs"
	"github.com/kernloom/kernloom-forge/internal/registry"
	"github.com/kernloom/kernloom-forge/internal/validator"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func loadReg(t *testing.T) *registry.Registry {
	t.Helper()
	reg, err := registry.LoadDir(filepath.Join(repoRoot(t), "registries", "core"))
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	return reg
}

func loadPolicy(t *testing.T, reg *registry.Registry, name string) validator.Policy {
	t.Helper()
	p, err := validator.ParsePolicyFile(filepath.Join(repoRoot(t), "examples", "policies", name))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	if err := validator.ValidatePolicy(&p, reg); err != nil {
		t.Fatalf("validate policy: %v", err)
	}
	return p
}

// ── Integration tests ─────────────────────────────────────────────────────────

func TestRenderMitigateConnectionSpike(t *testing.T) {
	reg := loadReg(t)
	policy := loadPolicy(t, reg, "mitigate-connection-spike.yaml")

	result, err := packs.RenderLocalPolicyPack(packs.RenderRequest{Policy: policy})
	if err != nil {
		t.Fatalf("RenderLocalPolicyPack: %v", err)
	}

	pack := result.Pack
	if pack.APIVersion != packs.LocalPolicyPackAPIVersion {
		t.Errorf("apiVersion: got %q, want %q", pack.APIVersion, packs.LocalPolicyPackAPIVersion)
	}
	if pack.Kind != packs.LocalPolicyPackKind {
		t.Errorf("kind: got %q, want %q", pack.Kind, packs.LocalPolicyPackKind)
	}
	if pack.Metadata.Name != "mitigate-src-connection-spike" {
		t.Errorf("name: got %q", pack.Metadata.Name)
	}

	// Must have at least one rule for the rate_limit action.
	if len(pack.Spec.Rules) == 0 {
		t.Fatal("expected at least one rule")
	}
	// Rule must use the Forge capability ID verbatim — not a KLIQ-internal ID.
	foundRateLimit := false
	for _, rule := range pack.Spec.Rules {
		if rule.Then.Capability == "enforce.traffic.rate_limit" {
			foundRateLimit = true
			if rule.When.FsmLevel != "soft" {
				t.Errorf("rate_limit rule fsm_level: got %q, want soft", rule.When.FsmLevel)
			}
			if rule.Then.Action != "rate_limit" {
				t.Errorf("rate_limit rule action: got %q, want rate_limit", rule.Then.Action)
			}
		}
	}
	if !foundRateLimit {
		t.Error("expected a rule with Forge capability enforce.traffic.rate_limit")
	}

	// capabilities_required must use Forge vocabulary.
	found := false
	for _, cap := range pack.Spec.CapabilitiesRequired {
		if cap == "enforce.traffic.rate_limit" {
			found = true
		}
	}
	if !found {
		t.Errorf("enforce.traffic.rate_limit not in capabilities_required: %v", pack.Spec.CapabilitiesRequired)
	}

	// max_action must be rate_limit (not block — this policy only rate-limits).
	if pack.Spec.Autonomy.MaxAction != "rate_limit" {
		t.Errorf("autonomy.max_action: got %q, want rate_limit", pack.Spec.Autonomy.MaxAction)
	}
	if pack.Spec.Autonomy.AllowLocalBlock {
		t.Error("allow_local_block should be false for a rate_limit policy")
	}
}

func TestRenderDOSPrevention(t *testing.T) {
	reg := loadReg(t)
	policy := loadPolicy(t, reg, "dos-prevention.yaml")

	result, err := packs.RenderLocalPolicyPack(packs.RenderRequest{Policy: policy})
	if err != nil {
		t.Fatalf("RenderLocalPolicyPack: %v", err)
	}
	// DOS policy uses enforce.network.deny → block level.
	if result.Pack.Spec.Autonomy.MaxAction != "block" {
		t.Errorf("dos-prevention max_action: got %q, want block", result.Pack.Spec.Autonomy.MaxAction)
	}
	if !result.Pack.Spec.Autonomy.AllowLocalBlock {
		t.Error("dos-prevention should have allow_local_block=true")
	}
}

func TestRenderQuarantineSourceOnlyIntentAction(t *testing.T) {
	// quarantine-source.yaml uses intent_action, not capability_action.
	// The renderer cannot expand intents yet — it requires the policy to be
	// pre-compiled to capability_actions first. This is expected to fail.
	reg := loadReg(t)
	policy := loadPolicy(t, reg, "quarantine-source.yaml")

	_, err := packs.RenderLocalPolicyPack(packs.RenderRequest{Policy: policy})
	if err == nil {
		t.Error("expected error: quarantine policy only has intent_action, not capability_action")
	}
}

func TestRenderWithDryRun(t *testing.T) {
	reg := loadReg(t)
	policy := loadPolicy(t, reg, "mitigate-connection-spike.yaml")

	result, err := packs.RenderLocalPolicyPack(packs.RenderRequest{Policy: policy, DryRun: true})
	if err != nil {
		t.Fatalf("RenderLocalPolicyPack: %v", err)
	}
	if !result.Pack.Spec.Autonomy.DryRun {
		t.Error("expected dry_run=true")
	}
}

func TestRenderWithForgeURL(t *testing.T) {
	reg := loadReg(t)
	policy := loadPolicy(t, reg, "mitigate-connection-spike.yaml")

	result, err := packs.RenderLocalPolicyPack(packs.RenderRequest{
		Policy:   policy,
		ForgeURL: "https://forge.example.com",
	})
	if err != nil {
		t.Fatalf("RenderLocalPolicyPack: %v", err)
	}
	if !result.Pack.Spec.Exports.Forge.Enabled {
		t.Error("expected forge export enabled")
	}
	if result.Pack.Spec.Exports.Forge.Endpoint != "https://forge.example.com" {
		t.Errorf("forge endpoint: got %q", result.Pack.Spec.Exports.Forge.Endpoint)
	}
}

// ── Unit tests with in-code fixtures ─────────────────────────────────────────

func TestRenderCapabilityMapping(t *testing.T) {
	cases := []struct {
		forgeCapability string
		wantKLIQ        string
		wantFSMLevel    string
		wantAction      string
	}{
		// Forge capability ID → expected output (Forge ID passed through, FSM level derived)
		{"enforce.traffic.rate_limit", "enforce.traffic.rate_limit", "soft", "rate_limit"},
		{"enforce.access.deny", "enforce.access.deny", "block", "block"},
		{"enforce.traffic.drop", "enforce.traffic.drop", "block", "block"},
		{"enforce.traffic.quarantine", "enforce.traffic.quarantine", "block", "block"},
		{"enforce.access.allow", "enforce.access.allow", "observe", "allow"},
		{"enforce.network.deny", "enforce.network.deny", "block", "block"},
		{"enforce.network.rate_limit", "enforce.network.rate_limit", "soft", "rate_limit"},
	}

	for _, tc := range cases {
		t.Run(tc.forgeCapability, func(t *testing.T) {
			policy := validator.Policy{Kind: "RuntimePolicy"}
			policy.Metadata.ID = "test-mapping"
			policy.Then = []validator.PolicyAction{
				{Type: "capability_action", Capability: tc.forgeCapability},
			}

			result, err := packs.RenderLocalPolicyPack(packs.RenderRequest{Policy: policy})
			if err != nil {
				t.Fatalf("RenderLocalPolicyPack: %v", err)
			}
			if len(result.Pack.Spec.Rules) == 0 {
				t.Fatal("no rules generated")
			}
			rule := result.Pack.Spec.Rules[0]
			if rule.Then.Capability != tc.wantKLIQ {
				t.Errorf("capability: got %q, want %q", rule.Then.Capability, tc.wantKLIQ)
			}
			if rule.When.FsmLevel != tc.wantFSMLevel {
				t.Errorf("fsm_level: got %q, want %q", rule.When.FsmLevel, tc.wantFSMLevel)
			}
			if rule.Then.Action != tc.wantAction {
				t.Errorf("action: got %q, want %q", rule.Then.Action, tc.wantAction)
			}
		})
	}
}

func TestRenderUnknownCapabilityWarned(t *testing.T) {
	policy := validator.Policy{Kind: "RuntimePolicy"}
	policy.Metadata.ID = "test-unknown-cap"
	policy.Then = []validator.PolicyAction{
		{Type: "capability_action", Capability: "analyze.baseline.compare"}, // no KLIQ mapping
		{Type: "capability_action", Capability: "enforce.access.deny"},       // has mapping
	}

	result, err := packs.RenderLocalPolicyPack(packs.RenderRequest{Policy: policy})
	if err != nil {
		t.Fatalf("RenderLocalPolicyPack: %v", err)
	}
	if len(result.Warnings) == 0 {
		t.Error("expected a warning for unmappable capability")
	}
	// analyze.baseline.compare is skipped, enforce.access.deny should still be rendered.
	if len(result.Pack.Spec.Rules) != 1 {
		t.Errorf("expected 1 rule (analyze skipped), got %d", len(result.Pack.Spec.Rules))
	}
}

func TestRenderNoMappableCapabilities(t *testing.T) {
	policy := validator.Policy{Kind: "RuntimePolicy"}
	policy.Metadata.ID = "test-no-mappable"
	policy.Then = []validator.PolicyAction{
		{Type: "capability_action", Capability: "analyze.baseline.compare"},
		{Type: "intent_action", Intent: "protection.source.quarantine"},
	}

	_, err := packs.RenderLocalPolicyPack(packs.RenderRequest{Policy: policy})
	if err == nil {
		t.Error("expected error when no capability can be mapped")
	}
}

func TestRenderMaxActionEscalation(t *testing.T) {
	// Mixed policy: one rate_limit + one block → max_action must be block.
	policy := validator.Policy{Kind: "RuntimePolicy"}
	policy.Metadata.ID = "test-mixed"
	policy.Then = []validator.PolicyAction{
		{Type: "capability_action", Capability: "enforce.traffic.rate_limit"},
		{Type: "capability_action", Capability: "enforce.access.deny"},
	}

	result, err := packs.RenderLocalPolicyPack(packs.RenderRequest{Policy: policy})
	if err != nil {
		t.Fatalf("RenderLocalPolicyPack: %v", err)
	}
	if result.Pack.Spec.Autonomy.MaxAction != "block" {
		t.Errorf("mixed policy: max_action should be block, got %q", result.Pack.Spec.Autonomy.MaxAction)
	}
	if !result.Pack.Spec.Autonomy.AllowLocalBlock {
		t.Error("mixed policy: allow_local_block should be true")
	}
	if len(result.Pack.Spec.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(result.Pack.Spec.Rules))
	}
}

func TestRenderTTLFromAction(t *testing.T) {
	policy := validator.Policy{Kind: "RuntimePolicy"}
	policy.Metadata.ID = "test-ttl"
	policy.Then = []validator.PolicyAction{
		{
			Type:       "capability_action",
			Capability: "enforce.traffic.rate_limit",
			TTL:        "15m",
		},
	}

	result, err := packs.RenderLocalPolicyPack(packs.RenderRequest{Policy: policy})
	if err != nil {
		t.Fatalf("RenderLocalPolicyPack: %v", err)
	}
	if result.Pack.Spec.Rules[0].Then.TTL != "15m" {
		t.Errorf("TTL: got %q, want 15m", result.Pack.Spec.Rules[0].Then.TTL)
	}
}

func TestRenderLabels(t *testing.T) {
	policy := validator.Policy{Kind: "RuntimePolicy"}
	policy.Metadata.ID = "test-labels"
	policy.Intent = "protection.abuse.mitigate"
	policy.Then = []validator.PolicyAction{
		{Type: "capability_action", Capability: "enforce.traffic.rate_limit"},
	}

	result, err := packs.RenderLocalPolicyPack(packs.RenderRequest{Policy: policy})
	if err != nil {
		t.Fatalf("RenderLocalPolicyPack: %v", err)
	}
	labels := result.Pack.Metadata.Labels
	if labels["forge.policy_id"] != "test-labels" {
		t.Errorf("forge.policy_id label: got %q", labels["forge.policy_id"])
	}
	if labels["forge.intent"] != "protection.abuse.mitigate" {
		t.Errorf("forge.intent label: got %q", labels["forge.intent"])
	}
}
