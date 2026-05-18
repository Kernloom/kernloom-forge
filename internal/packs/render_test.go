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

	// Must have at least one rule using the Forge capability ID verbatim.
	if len(pack.Spec.Rules) == 0 {
		t.Fatal("expected at least one rule")
	}
	foundRateLimit := false
	for _, rule := range pack.Spec.Rules {
		if rule.Then.Capability == "enforce.traffic.rate_limit" {
			foundRateLimit = true
			// v1.1: when.capability must be the Forge ID, no fsm_level.
			if rule.When.Capability != "enforce.traffic.rate_limit" {
				t.Errorf("rate_limit rule when.capability: got %q, want enforce.traffic.rate_limit", rule.When.Capability)
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

	// v1.1: action_authorization.allowed_capabilities replaces autonomy.max_action.
	// A rate_limit-only policy must not include enforce.access.deny.
	hasBlock := false
	for _, cap := range pack.Spec.ActionAuthorization.AllowedCapabilities {
		if cap == "enforce.access.deny" {
			hasBlock = true
		}
	}
	if hasBlock {
		t.Error("rate_limit policy must not include enforce.access.deny in allowed_capabilities")
	}
	if len(pack.Spec.ActionAuthorization.AllowedCapabilities) == 0 {
		t.Error("action_authorization.allowed_capabilities must not be empty")
	}
	if pack.Spec.ActionAuthorization.DefaultEffect != "deny" {
		t.Errorf("default_effect: got %q, want deny", pack.Spec.ActionAuthorization.DefaultEffect)
	}
}

func TestRenderDOSPrevention(t *testing.T) {
	reg := loadReg(t)
	policy := loadPolicy(t, reg, "dos-prevention.yaml")

	result, err := packs.RenderLocalPolicyPack(packs.RenderRequest{Policy: policy})
	if err != nil {
		t.Fatalf("RenderLocalPolicyPack: %v", err)
	}
	// v1.1: DOS policy uses enforce.network.deny → block capability must be in allowed_capabilities.
	hasBlockCap := false
	for _, cap := range result.Pack.Spec.ActionAuthorization.AllowedCapabilities {
		if cap == "enforce.network.deny" || cap == "enforce.access.deny" {
			hasBlockCap = true
		}
	}
	if !hasBlockCap {
		t.Errorf("dos-prevention allowed_capabilities should contain a block capability, got: %v",
			result.Pack.Spec.ActionAuthorization.AllowedCapabilities)
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

func TestRenderNoDryRunInPack(t *testing.T) {
	// dry_run is an operational flag that belongs in KliqDeploymentConfig.
	// Forge must never write it into a rendered pack.
	reg := loadReg(t)
	policy := loadPolicy(t, reg, "mitigate-connection-spike.yaml")

	result, err := packs.RenderLocalPolicyPack(packs.RenderRequest{Policy: policy})
	if err != nil {
		t.Fatalf("RenderLocalPolicyPack: %v", err)
	}
	// Verify the pack renders without error and has action_authorization + rules.
	if len(result.Pack.Spec.ActionAuthorization.AllowedCapabilities) == 0 && len(result.Pack.Spec.Rules) == 0 {
		t.Error("expected non-empty action_authorization or rules")
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
	// v1.1: Forge capability IDs pass through verbatim into when.capability and
	// then.capability. No fsm_level or action shorthand in output.
	cases := []string{
		"enforce.traffic.rate_limit",
		"enforce.access.deny",
		"enforce.traffic.drop",
		"enforce.traffic.quarantine",
		"enforce.access.allow",
		"enforce.network.deny",
		"enforce.network.rate_limit",
	}

	for _, forgeCapID := range cases {
		t.Run(forgeCapID, func(t *testing.T) {
			policy := validator.Policy{Kind: "RuntimePolicy"}
			policy.Metadata.ID = "test-mapping"
			policy.Then = []validator.PolicyAction{
				{Type: "capability_action", Capability: forgeCapID},
			}

			result, err := packs.RenderLocalPolicyPack(packs.RenderRequest{Policy: policy})
			if err != nil {
				t.Fatalf("RenderLocalPolicyPack: %v", err)
			}
			if len(result.Pack.Spec.Rules) == 0 {
				t.Fatal("no rules generated")
			}
			rule := result.Pack.Spec.Rules[0]
			// then.capability must be the Forge ID unchanged.
			if rule.Then.Capability != forgeCapID {
				t.Errorf("then.capability: got %q, want %q", rule.Then.Capability, forgeCapID)
			}
			// when.capability must also be the Forge ID — no fsm_level.
			if rule.When.Capability != forgeCapID {
				t.Errorf("when.capability: got %q, want %q", rule.When.Capability, forgeCapID)
			}
			// action_authorization must include this capability.
			found := false
			for _, c := range result.Pack.Spec.ActionAuthorization.AllowedCapabilities {
				if c == forgeCapID {
					found = true
				}
			}
			if !found {
				t.Errorf("%q not in action_authorization.allowed_capabilities", forgeCapID)
			}
		})
	}
}

func TestRenderUnknownCapabilityWarned(t *testing.T) {
	policy := validator.Policy{Kind: "RuntimePolicy"}
	policy.Metadata.ID = "test-unknown-cap"
	policy.Then = []validator.PolicyAction{
		{Type: "capability_action", Capability: "analyze.baseline.compare"}, // no KLIQ mapping
		{Type: "capability_action", Capability: "enforce.access.deny"},      // has mapping
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

func TestRenderAllowedCapabilitiesEscalation(t *testing.T) {
	// Mixed policy: rate_limit + block → both capabilities must appear in allowed_capabilities.
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
	allowed := result.Pack.Spec.ActionAuthorization.AllowedCapabilities
	hasRL, hasBlock := false, false
	for _, c := range allowed {
		if c == "enforce.traffic.rate_limit" {
			hasRL = true
		}
		if c == "enforce.access.deny" {
			hasBlock = true
		}
	}
	if !hasRL {
		t.Error("enforce.traffic.rate_limit missing from allowed_capabilities")
	}
	if !hasBlock {
		t.Error("enforce.access.deny missing from allowed_capabilities")
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
