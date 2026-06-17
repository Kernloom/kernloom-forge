// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bundler_test

import (
	"testing"
	"time"

	"github.com/kernloom/kernloom-forge/internal/signing"
	"github.com/kernloom/kernloom-forge/pkg/bundler"
	"github.com/kernloom/kernloom-forge/pkg/core/plan"
	"github.com/kernloom/kernloom-forge/pkg/core/profile"
)

// testProfile is a minimal enterprise_risk_overlay profile.
func testProfile() *profile.TargetIntegrationProfile {
	return &profile.TargetIntegrationProfile{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "TargetIntegrationProfile",
		Metadata:   profile.ProfileMetadata{Name: "openziti-production"},
		Spec: profile.ProfileSpec{
			AdapterRef: "openziti",
			Mode:       profile.ModeEnterpriseRiskOverlay,
			Runtime: profile.RuntimeSpec{
				Timing:      profile.TimingNearRuntime,
				Path:        profile.PathOutOfBand,
				Composition: profile.CompositionRestrictiveAnd,
				Constraints: profile.RuntimeConstraints{
					RestrictiveOnly:   true,
					RequireTTL:        true,
					RequireAudit:      true,
					RequireLease:      true,
					RequireAutoRevert: true,
				},
			},
			AllowedRuntimeActions: []string{
				"remove_kernloom_access_attribute",
				"identity.disable",
			},
		},
	}
}

// testEnforcementPlan simulates a compiler output with one compensating_control entry.
func testEnforcementPlan() *plan.EnforcementPlan {
	return &plan.EnforcementPlan{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "EnforcementPlan",
		Metadata: plan.PlanMetadata{
			Name:         "investor-apps-openziti-production",
			SourcePolicy: "investor-apps-access",
			Target:       "openziti-production",
			CompiledAt:   time.Now().UTC(),
		},
		Spec: plan.EnforcementPlanSpec{
			Requirements: []plan.RequirementEnforcement{
				{
					ID:              "subject-identity",
					RequirementKind: "subject_identity",
					Status:          plan.StatusImplemented,
					Capability:      "identity.role_attributes",
					Fidelity:        "high",
				},
				{
					ID:              "resource-identity",
					RequirementKind: "resource_identity",
					Status:          plan.StatusImplemented,
					Capability:      "resource.service_definition",
					Fidelity:        "high",
				},
				{
					ID:              "require-mfa",
					RequirementKind: "auth_strength",
					Requirement:     "subject.auth_strength >= 'mfa'",
					Status:          plan.StatusDelegated,
					Delegation: &plan.DelegationNote{
						EvaluationOwner: "openziti-controller",
					},
				},
				{
					ID:              "require-low-risk",
					RequirementKind: "risk_level",
					Requirement:     "subject.risk.level == 'low'",
					Status:          plan.StatusCompensatingControl,
					ActionBinding: &plan.ActionBinding{
						Action:        "remove_kernloom_access_attribute",
						Attribute:     "kl.access.active",
						MaxTTL:        "30m",
						DecisionOwner: "kernloom-runtime-pdp",
					},
					Ownership: &plan.RequirementOwnership{
						RiskAssessmentOwner:      "kernloom-risk-engine",
						EnterpriseDecisionOwner:  "kernloom-runtime-pdp",
						TargetAuthorizationOwner: "openziti-controller",
						EnforcementOwner:         "openziti-edge-router",
					},
				},
				{
					ID:              "require-healthy-device",
					RequirementKind: "device_posture",
					Status:          plan.StatusPartial,
					Downgrade: &plan.DowngradeNote{
						From:   "Enterprise posture: healthy",
						To:     "OpenZiti posture check: binary pass/fail",
						Reason: "OpenZiti posture checks are binary and static",
					},
				},
			},
			Summary: plan.PlanSummary{
				Deployable:           true,
				RuntimeModel:         "enterprise_risk_overlay",
				SemanticFidelity:     "medium",
				CompensatingControls: []string{"require-low-risk"},
				Downgrades:           []string{"require-healthy-device"},
			},
		},
	}
}

func testBundleConfig() bundler.BundleConfig {
	return bundler.BundleConfig{
		NodeID:                 "node-edge-01",
		TenantID:               "acme-corp",
		Generation:             1,
		IssuedAt:               time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		ValidFor:               24 * time.Hour,
		ContextRegistryVersion: "1.0",
		ActiveAdapters:         []string{"openziti-pip", "openziti-action-adapter"},
		RiskModelName:          "enterprise-access-risk",
		RiskModelVersion:       "1.0.0",
		BaselineEnabled:        true,
		GraphEnabled:           true,
	}
}

func TestBuild_ProducesSignedBundle(t *testing.T) {
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	b, err := bundler.Build(testEnforcementPlan(), testProfile(), testBundleConfig(), priv)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if b.Kind != "RuntimeBundle" {
		t.Errorf("Kind = %q, want RuntimeBundle", b.Kind)
	}
	if b.Signature == "" {
		t.Error("Signature must not be empty")
	}
	if b.Metadata.SpecHash == "" {
		t.Error("SpecHash must not be empty")
	}
	if b.Metadata.Generation != 1 {
		t.Errorf("Generation = %d, want 1", b.Metadata.Generation)
	}

	// Verify signature and hash.
	if err := bundler.Verify(b, pub); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestBuild_RuntimePolicyPackContainsCompensatingRules(t *testing.T) {
	_, priv, _ := signing.GenerateKeyPair()
	b, err := bundler.Build(testEnforcementPlan(), testProfile(), testBundleConfig(), priv)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	policies := b.Spec.PolicyPack.Spec.Policies
	if len(policies) == 0 {
		t.Fatal("expected at least one RuntimePolicy from compensating_control requirement")
	}

	// The risk_level compensating_control should produce a rule.
	found := false
	for _, p := range policies {
		if p.When.Language == "cel" && p.When.Expression != "" {
			found = true
			if p.Effect.Capability == "" {
				t.Errorf("policy %q: capability must not be empty", p.ID)
			}
			if p.Effect.TTL == 0 {
				t.Errorf("policy %q: TTL must be set", p.ID)
			}
			if p.MissingContextBehavior == "" {
				t.Errorf("policy %q: MissingContextBehavior must be set", p.ID)
			}
		}
	}
	if !found {
		t.Error("no CEL rule found in RuntimePolicyPack")
	}
}

func TestBuild_PDPProfileReflectsProfile(t *testing.T) {
	_, priv, _ := signing.GenerateKeyPair()
	b, err := bundler.Build(testEnforcementPlan(), testProfile(), testBundleConfig(), priv)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	pdp := b.Spec.PDPProfile
	if pdp.Kind != "RuntimePDPProfile" {
		t.Errorf("PDPProfile.Kind = %q, want RuntimePDPProfile", pdp.Kind)
	}
	if pdp.Spec.LocalRiskMode == "" {
		t.Error("LocalRiskMode must not be empty")
	}
	if len(pdp.Spec.AllowedCapabilities) == 0 {
		t.Error("AllowedCapabilities must not be empty")
	}
	if pdp.Spec.MaxTTL == 0 {
		t.Error("MaxTTL must not be zero")
	}
}

func TestVerify_TamperedSpec(t *testing.T) {
	pub, priv, _ := signing.GenerateKeyPair()
	b, _ := bundler.Build(testEnforcementPlan(), testProfile(), testBundleConfig(), priv)

	// Tamper with the spec after signing.
	b.Spec.PolicyPack.Metadata.Name = "tampered-name"

	if err := bundler.Verify(b, pub); err == nil {
		t.Error("Verify should fail for tampered bundle")
	}
}

func TestVerify_Expired(t *testing.T) {
	_, priv, _ := signing.GenerateKeyPair()
	cfg := testBundleConfig()
	cfg.IssuedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg.ValidFor = 24 * time.Hour

	b, _ := bundler.Build(testEnforcementPlan(), testProfile(), cfg, priv)

	// Check against a time well after expiry.
	futureNow := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	if err := bundler.VerifyNotExpired(b, futureNow); err == nil {
		t.Error("VerifyNotExpired should fail for expired bundle")
	}
}

func TestVerify_NotExpired(t *testing.T) {
	_, priv, _ := signing.GenerateKeyPair()
	b, _ := bundler.Build(testEnforcementPlan(), testProfile(), testBundleConfig(), priv)

	// Should not be expired immediately after issuance.
	if err := bundler.VerifyNotExpired(b, b.Metadata.IssuedAt.Add(time.Hour)); err != nil {
		t.Errorf("VerifyNotExpired: %v", err)
	}
}

func TestBuild_MonotonicGeneration(t *testing.T) {
	_, priv, _ := signing.GenerateKeyPair()
	cfg := testBundleConfig()
	cfg.Generation = 0 // invalid

	_, err := bundler.Build(testEnforcementPlan(), testProfile(), cfg, priv)
	if err == nil {
		t.Error("generation=0 should be rejected")
	}
}

func TestBuild_DelegatedAndPartialNotInPack(t *testing.T) {
	_, priv, _ := signing.GenerateKeyPair()
	b, _ := bundler.Build(testEnforcementPlan(), testProfile(), testBundleConfig(), priv)

	// Delegated and partial requirements must NOT generate RuntimePolicy rules.
	// Only compensating_control requirements produce rules.
	for _, p := range b.Spec.PolicyPack.Spec.Policies {
		// No rule should reference the delegated "require-mfa" requirement.
		if p.ID == "require-mfa" {
			t.Errorf("delegated requirement should not produce a RuntimePolicy rule: %s", p.ID)
		}
	}
}
