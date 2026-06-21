// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bundler_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom-forge/pkg/bundler"
	"github.com/kernloom/kernloom-forge/pkg/core/plan"
	"github.com/kernloom/kernloom-forge/pkg/core/profile"
	"gopkg.in/yaml.v3"
)

func TestBuildPolicyPackUsesKLIQContracts(t *testing.T) {
	pack, err := bundler.BuildPolicyPack(testEnforcementPlan(), testProfile(), bundler.RuntimePolicyConfig{
		IssuedAt:   fixedNow(),
		DefaultTTL: time.Minute,
		Guardrails: []contracts.RuntimeGuardrail{{
			ID:   "never-auto-block-admins",
			Type: "never",
			Subject: contracts.RuntimeGuardrailSubject{
				Type: "group",
				Ref:  "kernloom-admins",
			},
			ForbiddenActions: []string{"enforce.access.deny"},
		}},
		DetectionRules: []contracts.RuntimeDetectionRule{{
			ID:          "admin-deny",
			Type:        "access.denied_threshold",
			ResourceRef: "ziti-controller",
			Subject: contracts.RuntimeDetectionSubject{
				Type: "group",
				Ref:  "kernloom-admins",
			},
			Threshold: 5,
			Window:    contracts.NewDuration(15 * time.Minute),
			Scope:     "source",
		}},
		ResponseRules: []contracts.RuntimeResponseRule{{
			ID: "denied-access-alert",
			When: contracts.RuntimeResponseTrigger{
				Detection: "admin-deny",
			},
			Then: []contracts.RuntimeResponseAction{{
				ID:       "notify.alert.emit",
				Route:    "alert-route.security-ops",
				Severity: "medium",
				Dedupe:   contracts.NewDuration(15 * time.Minute),
			}},
		}},
		AlertRoutes: []contracts.RuntimeAlertRoute{{
			ID: "alert-route.security-ops",
			Channels: []contracts.RuntimeAlertChannel{{
				Type: "slack",
				Ref:  "channel.security-ops",
			}},
			DefaultSeverity: "medium",
		}},
	})
	if err != nil {
		t.Fatalf("BuildPolicyPack: %v", err)
	}
	if pack.APIVersion != contracts.RuntimeAPIVersion || pack.Kind != contracts.KindRuntimePolicyPack {
		t.Fatalf("unexpected TypeMeta: %#v", pack.TypeMeta)
	}
	if len(pack.Spec.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(pack.Spec.Rules))
	}
	rule := pack.Spec.Rules[0]
	if rule.When != "risk.level in ['high', 'critical']" {
		t.Fatalf("when = %q", rule.When)
	}
	if rule.Then.Capability != "enforce.access.deny" || rule.Then.Level != "block" {
		t.Fatalf("action = %#v", rule.Then)
	}
	if rule.Then.TTL.Duration != time.Minute {
		t.Fatalf("ttl = %s", rule.Then.TTL.Duration)
	}
	if len(pack.Spec.Guardrails) != 1 {
		t.Fatalf("guardrails = %d, want 1", len(pack.Spec.Guardrails))
	}
	if pack.Spec.Guardrails[0].Subject.Ref != "kernloom-admins" {
		t.Fatalf("guardrail not preserved: %#v", pack.Spec.Guardrails[0])
	}
	if len(pack.Spec.DetectionRules) != 1 || pack.Spec.DetectionRules[0].ID != "admin-deny" {
		t.Fatalf("detection rules not preserved: %#v", pack.Spec.DetectionRules)
	}
	if len(pack.Spec.ResponseRules) != 1 || pack.Spec.ResponseRules[0].When.Detection != "admin-deny" || pack.Spec.ResponseRules[0].Then[0].Route != "alert-route.security-ops" {
		t.Fatalf("response rules not preserved: %#v", pack.Spec.ResponseRules)
	}
	if len(pack.Spec.AlertRoutes) != 1 || pack.Spec.AlertRoutes[0].ID != "alert-route.security-ops" {
		t.Fatalf("alert routes not preserved: %#v", pack.Spec.AlertRoutes)
	}
}

func TestBuildPolicyPackDoesNotDenyOnUnknownContext(t *testing.T) {
	pack, err := bundler.BuildPolicyPack(testContextSensitiveEnforcementPlan(), testProfile(), bundler.RuntimePolicyConfig{
		IssuedAt:   fixedNow(),
		DefaultTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("BuildPolicyPack: %v", err)
	}
	if len(pack.Spec.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(pack.Spec.Rules))
	}

	want := map[string]string{
		"compensating-require-healthy-device-openziti-production": "device.posture.status in ['degraded', 'unhealthy']",
		"compensating-require-mfa-openziti-production":            "session.authentication.strength in ['none', 'password']",
	}
	for _, rule := range pack.Spec.Rules {
		expected, ok := want[rule.ID]
		if !ok {
			t.Fatalf("unexpected rule %q", rule.ID)
		}
		if rule.When != expected {
			t.Fatalf("rule %q when = %q, want %q", rule.ID, rule.When, expected)
		}
		if strings.Contains(rule.When, "unknown") || strings.HasPrefix(rule.When, "!(") {
			t.Fatalf("rule %q should not treat unknown or missing context as a deny trigger: %q", rule.ID, rule.When)
		}
	}
}

func TestBuildPolicyPackYAMLIsLoadableByKLIQShape(t *testing.T) {
	pack, err := bundler.BuildPolicyPack(testEnforcementPlan(), testProfile(), bundler.RuntimePolicyConfig{
		IssuedAt:   fixedNow(),
		DefaultTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("BuildPolicyPack: %v", err)
	}
	raw, err := yaml.Marshal(pack)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	text := string(raw)
	for _, needle := range []string{"apiVersion:", "kind: RuntimePolicyPack", "capabilities_required:", "ttl: 1m0s"} {
		if !strings.Contains(text, needle) {
			t.Fatalf("YAML missing %q:\n%s", needle, text)
		}
	}
}

func TestBuildProducesSignedContractsBundle(t *testing.T) {
	pub, priv := keypair(t)
	b, err := bundler.Build(testEnforcementPlan(), testProfile(), testBundleConfig(), priv)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if b.APIVersion != contracts.RuntimeAPIVersion || b.Kind != contracts.KindRuntimeBundle {
		t.Fatalf("unexpected bundle TypeMeta: %#v", b.TypeMeta)
	}
	if b.Signature.Value == "" {
		t.Fatal("bundle is not signed")
	}
	if b.Spec.RuntimePolicyPack.Kind != contracts.KindRuntimePolicyPack {
		t.Fatalf("embedded pack kind = %q", b.Spec.RuntimePolicyPack.Kind)
	}
	if b.Spec.RegistrySnapshot.Ref.Name == "" || b.Spec.RegistrySnapshot.Ref.Digest == "" {
		t.Fatalf("registry snapshot was not embedded: %#v", b.Spec.RegistrySnapshot.Ref)
	}
	if err := contracts.VerifyRuntimeBundle(b, pub, fixedNow()); err != nil {
		t.Fatalf("VerifyRuntimeBundle: %v", err)
	}
}

func TestVerifyRejectsTamperedBundle(t *testing.T) {
	pub, priv := keypair(t)
	b, err := bundler.Build(testEnforcementPlan(), testProfile(), testBundleConfig(), priv)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	b.Spec.RuntimePolicyPack.Spec.Rules[0].When = "risk.level == 'low'"
	if err := bundler.Verify(b, pub, fixedNow()); err == nil {
		t.Fatal("Verify should reject tampered bundle")
	}
}

func TestContractsBundleJSONRoundTrip(t *testing.T) {
	_, priv := keypair(t)
	b, err := bundler.Build(testEnforcementPlan(), testProfile(), testBundleConfig(), priv)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var decoded contracts.RuntimeBundle
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if decoded.Metadata.NodeID != "node-edge-01" || decoded.Spec.RuntimePolicyPack.Kind != contracts.KindRuntimePolicyPack {
		t.Fatalf("decoded bundle mismatch: %#v", decoded)
	}
}

func TestVerifyNotExpired(t *testing.T) {
	_, priv := keypair(t)
	b, err := bundler.Build(testEnforcementPlan(), testProfile(), testBundleConfig(), priv)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := bundler.VerifyNotExpired(b, fixedNow().Add(time.Hour)); err != nil {
		t.Fatalf("VerifyNotExpired: %v", err)
	}
	if err := bundler.VerifyNotExpired(b, fixedNow().Add(48*time.Hour)); err == nil {
		t.Fatal("VerifyNotExpired should reject expired bundle")
	}
}

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
			AllowedRuntimeActions: []string{"remove_kernloom_access_attribute"},
		},
	}
}

func testEnforcementPlan() *plan.EnforcementPlan {
	return &plan.EnforcementPlan{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "EnforcementPlan",
		Metadata: plan.PlanMetadata{
			Name:         "investor-apps-openziti-production",
			SourcePolicy: "investor-apps-access",
			Target:       "openziti-production",
			CompiledAt:   fixedNow(),
		},
		Spec: plan.EnforcementPlanSpec{
			Requirements: []plan.RequirementEnforcement{{
				ID:              "require-low-risk",
				RequirementKind: "risk_level",
				Requirement:     "subject.risk.level == 'low'",
				Status:          plan.StatusCompensatingControl,
				ActionBinding: &plan.ActionBinding{
					Action:        "remove_kernloom_access_attribute",
					Attribute:     "kl.access.active",
					DecisionOwner: "kernloom-runtime-pdp",
				},
			}},
			Summary: plan.PlanSummary{
				Deployable:           true,
				RuntimeModel:         "enterprise_risk_overlay",
				SemanticFidelity:     "medium",
				CompensatingControls: []string{"require-low-risk"},
			},
		},
	}
}

func testContextSensitiveEnforcementPlan() *plan.EnforcementPlan {
	return &plan.EnforcementPlan{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "EnforcementPlan",
		Metadata: plan.PlanMetadata{
			Name:         "edge-access-openziti-production",
			SourcePolicy: "edge-access",
			Target:       "openziti-production",
			CompiledAt:   fixedNow(),
		},
		Spec: plan.EnforcementPlanSpec{
			Requirements: []plan.RequirementEnforcement{
				{
					ID:              "require-healthy-device",
					RequirementKind: "device_posture",
					Requirement:     "device.posture.status == 'healthy'",
					Status:          plan.StatusCompensatingControl,
					ActionBinding: &plan.ActionBinding{
						Action:        "remove_kernloom_access_attribute",
						Attribute:     "kl.access.active",
						DecisionOwner: "kernloom-runtime-pdp",
					},
				},
				{
					ID:              "require-mfa",
					RequirementKind: "auth_strength",
					Requirement:     "session.authentication.strength in ['mfa', 'phishing_resistant_mfa']",
					Status:          plan.StatusCompensatingControl,
					ActionBinding: &plan.ActionBinding{
						Action:        "remove_kernloom_access_attribute",
						Attribute:     "kl.access.active",
						DecisionOwner: "kernloom-runtime-pdp",
					},
				},
			},
			Summary: plan.PlanSummary{
				Deployable:           true,
				RuntimeModel:         "enterprise_risk_overlay",
				SemanticFidelity:     "medium",
				CompensatingControls: []string{"require-healthy-device", "require-mfa"},
			},
		},
	}
}

func testBundleConfig() bundler.BundleConfig {
	return bundler.BundleConfig{
		NodeID:                 "node-edge-01",
		TenantID:               "acme-corp",
		Generation:             1,
		IssuedAt:               fixedNow(),
		ValidFor:               24 * time.Hour,
		ContextRegistryVersion: "1.0",
		PreferredAdapters:      []string{"openziti"},
		RuntimePDPMode:         "active",
		FailoverBehavior:       "fail_static",
		DefaultTTL:             time.Minute,
		BaselineEnabled:        true,
		GraphEnabled:           true,
	}
}

func fixedNow() time.Time {
	return time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC)
}

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return pub, priv
}
