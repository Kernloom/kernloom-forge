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
				Type: "log",
				Ref:  "log.security-ops",
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

func TestBuildPolicyPackExplicitResponseOverridesRiskCompensatingControl(t *testing.T) {
	pack, err := bundler.BuildPolicyPack(testKlshieldEnforcementPlan(), testKlshieldProfile(), bundler.RuntimePolicyConfig{
		IssuedAt:   fixedNow(),
		DefaultTTL: time.Minute,
		DetectionRules: []contracts.RuntimeDetectionRule{{
			ID:        "risk-medium",
			Type:      "metric.threshold",
			Threshold: 1,
			Params: map[string]any{
				"key":      "subject.risk.level",
				"operator": "eq",
				"value":    "medium",
			},
		}},
		ResponseRules: []contracts.RuntimeResponseRule{{
			ID:   "rate-limit-risk-medium",
			When: contracts.RuntimeResponseTrigger{Detection: "risk-medium"},
			Then: []contracts.RuntimeResponseAction{{
				ID:     "enforce.traffic.rate_limit",
				TTL:    contracts.NewDuration(15 * time.Minute),
				Target: contracts.RuntimeResponseTarget{Scope: "source"},
			}},
		}},
	})
	if err != nil {
		t.Fatalf("BuildPolicyPack: %v", err)
	}
	if len(pack.Spec.Rules) != 1 {
		t.Fatalf("rules = %d, want only explicit response rule: %#v", len(pack.Spec.Rules), pack.Spec.Rules)
	}
	rule := pack.Spec.Rules[0]
	if strings.HasPrefix(rule.ID, "compensating-") {
		t.Fatalf("risk compensating control must not bypass explicit response policy: %#v", rule)
	}
	if rule.Then.Capability != "enforce.traffic.rate_limit" {
		t.Fatalf("response capability = %q", rule.Then.Capability)
	}
}

func TestBuildPolicyPackCarriesAutonomyLifecycle(t *testing.T) {
	pack, err := bundler.BuildPolicyPack(testKlshieldEnforcementPlan(), testKlshieldProfile(), bundler.RuntimePolicyConfig{
		IssuedAt: fixedNow(),
		AutonomyLifecycle: &contracts.RuntimeAutonomyLifecycleSpec{
			Hold: []contracts.RuntimeAutonomyHoldRule{{
				ID: "hold-enforcement-feedback",
				While: contracts.RuntimeAutonomyHoldCondition{
					EnforcementFeedbackActive: true,
					Levels:                    []string{"soft", "hard", "block"},
				},
				Action: contracts.RuntimeActionSpec{
					Capability: "enforce.traffic.rate_limit",
					Level:      "hard",
					TTL:        contracts.NewDuration(30 * time.Second),
					Params:     map[string]any{"rate_pps": 100},
				},
				ReasonCodes: []string{"enforcement_hold"},
			}},
			StepDown: contracts.RuntimeAutonomyStepDown{
				CleanAfter:   contracts.NewDuration(30 * time.Second),
				ObserveAfter: contracts.NewDuration(2 * time.Minute),
			},
			MaxRenewals: 3,
		},
	})
	if err != nil {
		t.Fatalf("BuildPolicyPack: %v", err)
	}
	if pack.Spec.AutonomyLifecycle == nil || len(pack.Spec.AutonomyLifecycle.Hold) != 1 {
		t.Fatalf("autonomy lifecycle not carried: %#v", pack.Spec.AutonomyLifecycle)
	}
	if got := pack.Spec.AutonomyLifecycle.Hold[0].Action.Params["audit_required"]; got != true {
		t.Fatalf("autonomy action contract params not normalized: %#v", pack.Spec.AutonomyLifecycle.Hold[0].Action.Params)
	}
	if !containsString(pack.Spec.CapabilitiesRequired, "enforce.traffic.rate_limit") {
		t.Fatalf("rate-limit capability missing: %#v", pack.Spec.CapabilitiesRequired)
	}
}

func TestBuildPolicyPackRejectsResponseActionWithoutTTL(t *testing.T) {
	_, err := bundler.BuildPolicyPack(testEnforcementPlan(), testProfile(), bundler.RuntimePolicyConfig{
		IssuedAt:   fixedNow(),
		DefaultTTL: time.Minute,
		DetectionRules: []contracts.RuntimeDetectionRule{{
			ID:        "risk-high",
			Type:      "metric.threshold",
			Threshold: 1,
			Params: map[string]any{
				"key":      "subject.risk.level",
				"operator": "eq",
				"value":    "high",
			},
		}},
		ResponseRules: []contracts.RuntimeResponseRule{{
			ID: "block-without-ttl",
			When: contracts.RuntimeResponseTrigger{
				Detection: "risk-high",
			},
			Then: []contracts.RuntimeResponseAction{{
				ID: "enforce.traffic.drop",
			}},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "requires ttl") {
		t.Fatalf("expected missing TTL validation error, got %v", err)
	}
}

func TestBuildPolicyPackRejectsRuntimeTTLAboveContractMax(t *testing.T) {
	_, err := bundler.BuildPolicyPack(testEnforcementPlan(), testProfile(), bundler.RuntimePolicyConfig{
		IssuedAt:   fixedNow(),
		DefaultTTL: 2 * time.Hour,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds maxTTL") {
		t.Fatalf("expected maxTTL validation error, got %v", err)
	}
}

func TestBuildPolicyPackRejectsGrantingResponseAction(t *testing.T) {
	_, err := bundler.BuildPolicyPack(testEnforcementPlan(), testProfile(), bundler.RuntimePolicyConfig{
		IssuedAt:   fixedNow(),
		DefaultTTL: time.Minute,
		DetectionRules: []contracts.RuntimeDetectionRule{{
			ID:        "risk-high",
			Type:      "metric.threshold",
			Threshold: 1,
			Params: map[string]any{
				"key":      "subject.risk.level",
				"operator": "eq",
				"value":    "high",
			},
		}},
		ResponseRules: []contracts.RuntimeResponseRule{{
			ID: "grant-in-runtime-response",
			When: contracts.RuntimeResponseTrigger{
				Detection: "risk-high",
			},
			Then: []contracts.RuntimeResponseAction{{
				ID:  "enforce.network.allow",
				TTL: contracts.NewDuration(time.Minute),
			}},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "grants access") {
		t.Fatalf("expected grant validation error, got %v", err)
	}
}

func TestBuildPolicyPackCompilesResponseEnforcementIntoRuntimeRules(t *testing.T) {
	prof := testKlshieldProfile()
	prof.Spec.AllowedRuntimeActions = append(prof.Spec.AllowedRuntimeActions, "network.block_source")
	pack, err := bundler.BuildPolicyPack(testKlshieldEnforcementPlan(), prof, bundler.RuntimePolicyConfig{
		IssuedAt:   fixedNow(),
		DefaultTTL: time.Minute,
		DetectionRules: []contracts.RuntimeDetectionRule{{
			ID:        "risk-high",
			Type:      "metric.threshold",
			Threshold: 1,
			Params: map[string]any{
				"key":      "subject.risk.level",
				"operator": "in",
				"value":    []string{"high", "critical"},
			},
		}, {
			ID:          "sustained-pressure",
			Type:        "source.rate_limit_drops_sustained",
			ResourceRef: "public-edge",
			Threshold:   1,
			Window:      contracts.NewDuration(5 * time.Minute),
			Scope:       "source",
			Subject:     contracts.RuntimeDetectionSubject{Selector: "unknown_source"},
		}},
		ResponseRules: []contracts.RuntimeResponseRule{{
			ID:   "rate-limit-risk-high",
			When: contracts.RuntimeResponseTrigger{Detection: "risk-high"},
			Then: []contracts.RuntimeResponseAction{{
				ID:     "enforce.traffic.rate_limit",
				TTL:    contracts.NewDuration(15 * time.Minute),
				Target: contracts.RuntimeResponseTarget{Scope: "source"},
			}},
		}, {
			ID:   "block-after-pressure",
			When: contracts.RuntimeResponseTrigger{Detection: "sustained-pressure"},
			Then: []contracts.RuntimeResponseAction{{
				ID:     "enforce.traffic.drop",
				TTL:    contracts.NewDuration(5 * time.Minute),
				Target: contracts.RuntimeResponseTarget{Scope: "source"},
				Params: map[string]any{
					"previous_action_id":       "enforce.traffic.rate_limit",
					"previous_action_active":   true,
					"previous_action_evidence": []string{"runtime_response_state", "local_runtime_state"},
					"min_risk_confidence":      0.8,
					"max_risk_age_seconds":     120,
					"min_independent_signals":  2,
				},
			}},
		}},
	})
	if err != nil {
		t.Fatalf("BuildPolicyPack: %v", err)
	}
	var riskRule, pressureRule *contracts.RuntimePolicyRule
	for i := range pack.Spec.Rules {
		switch pack.Spec.Rules[i].ID {
		case "response-rate-limit-risk-high-enforce-traffic-rate-limit":
			riskRule = &pack.Spec.Rules[i]
		case "response-block-after-pressure-enforce-traffic-drop":
			pressureRule = &pack.Spec.Rules[i]
		}
	}
	if riskRule == nil {
		t.Fatalf("missing risk response runtime rule: %#v", pack.Spec.Rules)
	}
	if riskRule.When != "risk.level in ['high', 'critical']" {
		t.Fatalf("risk when = %q", riskRule.When)
	}
	if riskRule.Then.Capability != "enforce.traffic.rate_limit" || riskRule.Then.Level != "hard" {
		t.Fatalf("risk action = %#v", riskRule.Then)
	}
	if pressureRule == nil {
		t.Fatalf("missing pressure response runtime rule: %#v", pack.Spec.Rules)
	}
	if !strings.Contains(pressureRule.When, "detections.sustained_pressure.active == true") {
		t.Fatalf("pressure when missing detection fact: %q", pressureRule.When)
	}
	if !strings.Contains(pressureRule.When, "actions.enforce_traffic_rate_limit.active == true") {
		t.Fatalf("pressure when missing previous action fact: %q", pressureRule.When)
	}
	if !strings.Contains(pressureRule.When, "actions.enforce_traffic_rate_limit.dry_run == true") {
		t.Fatalf("pressure when missing dry-run projection: %q", pressureRule.When)
	}
	if !strings.Contains(pressureRule.When, "actions.enforce_traffic_rate_limit.elapsed_seconds >= 300") {
		t.Fatalf("pressure when missing sustained dry-run age guard: %q", pressureRule.When)
	}
	if !strings.Contains(pressureRule.When, "fsm.current_level in ['soft', 'hard']") {
		t.Fatalf("pressure when missing local runtime evidence: %q", pressureRule.When)
	}
	if !strings.Contains(pressureRule.When, "risk.confidence >= 0.8") {
		t.Fatalf("pressure when missing risk confidence guard: %q", pressureRule.When)
	}
	if !strings.Contains(pressureRule.When, "risk.age_seconds <= 120") {
		t.Fatalf("pressure when missing risk freshness guard: %q", pressureRule.When)
	}
	if !strings.Contains(pressureRule.When, "risk.independent_signal_count >= 2") {
		t.Fatalf("pressure when missing independent signal guard: %q", pressureRule.When)
	}
	if pressureRule.Then.Capability != "enforce.traffic.drop" || pressureRule.Then.Level != "block" {
		t.Fatalf("pressure action = %#v", pressureRule.Then)
	}
	if got := pressureRule.Then.Params["source_class"]; got != "unknown" {
		t.Fatalf("source_class = %#v", got)
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

func TestBuildProducesKLShieldGoldenRuntimeBundle(t *testing.T) {
	pub, priv := keypair(t)
	b, err := bundler.Build(testKlshieldEnforcementPlan(), testKlshieldProfile(), bundler.BundleConfig{
		NodeID:            "node-klshield-01",
		Generation:        7,
		IssuedAt:          fixedNow(),
		ValidFor:          time.Hour,
		PreferredAdapters: []string{"klshield"},
		RuntimePDPMode:    "active",
		DefaultTTL:        time.Minute,
		Guardrails: []contracts.RuntimeGuardrail{{
			ID:   "never-auto-block-admins",
			Type: "never",
			Subject: contracts.RuntimeGuardrailSubject{
				Type: "group",
				Ref:  "kernloom-admins",
			},
			ForbiddenActions: []string{"enforce.access.deny", "enforce.traffic.drop"},
			Enforcement: contracts.RuntimeGuardrailEnforcement{
				ViolationBehavior: "reject_action",
				UnknownBehavior:   "reject_hard_action",
			},
		}},
		DetectionRules: []contracts.RuntimeDetectionRule{{
			ID:          "unknown-source-heavy-deny",
			Type:        "access.denied_threshold",
			ResourceRef: "ziti-controller",
			Threshold:   20,
			Window:      contracts.NewDuration(15 * time.Minute),
			Scope:       "source",
		}},
		AlertRoutes: []contracts.RuntimeAlertRoute{{
			ID: "alert-route.security-ops",
			Channels: []contracts.RuntimeAlertChannel{{
				Type: "email",
				Ref:  "channel.security-ops",
			}},
			DefaultSeverity: "high",
			Deduplication: contracts.RuntimeAlertDeduplication{
				Enabled: true,
				Window:  contracts.NewDuration(15 * time.Minute),
				Keys:    []string{"resource.id", "detection.id", "source.identity_or_ip"},
			},
		}},
		ResponseRules: []contracts.RuntimeResponseRule{{
			ID:   "rate-limit-unknown-source-heavy-deny",
			When: contracts.RuntimeResponseTrigger{Detection: "unknown-source-heavy-deny"},
			Then: []contracts.RuntimeResponseAction{{
				ID:     "enforce.traffic.rate_limit",
				TTL:    contracts.NewDuration(10 * time.Minute),
				Target: contracts.RuntimeResponseTarget{Scope: "source.ip"},
			}, {
				ID:       "notify.alert.emit",
				Route:    "alert-route.security-ops",
				Severity: "high",
				Dedupe:   contracts.NewDuration(15 * time.Minute),
			}},
		}},
	}, priv)
	if err != nil {
		t.Fatalf("Build klshield golden bundle: %v", err)
	}
	if err := contracts.VerifyRuntimeBundle(b, pub, fixedNow()); err != nil {
		t.Fatalf("VerifyRuntimeBundle: %v", err)
	}
	if got := b.Spec.AdapterSelector.PreferredAdapters; len(got) != 1 || got[0] != "klshield" {
		t.Fatalf("preferred adapters = %#v", got)
	}
	if len(b.Spec.RuntimePolicyPack.Spec.Guardrails) != 1 {
		t.Fatalf("guardrails not carried: %#v", b.Spec.RuntimePolicyPack.Spec.Guardrails)
	}
	if len(b.Spec.RuntimePolicyPack.Spec.ResponseRules) != 1 || len(b.Spec.RuntimePolicyPack.Spec.AlertRoutes) != 1 {
		t.Fatalf("response IR not carried: responses=%#v routes=%#v", b.Spec.RuntimePolicyPack.Spec.ResponseRules, b.Spec.RuntimePolicyPack.Spec.AlertRoutes)
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

func testKlshieldProfile() *profile.TargetIntegrationProfile {
	return &profile.TargetIntegrationProfile{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "TargetIntegrationProfile",
		Metadata:   profile.ProfileMetadata{Name: "klshield-local"},
		Spec: profile.ProfileSpec{
			AdapterRef: "klshield",
			Mode:       profile.ModeKernloomPDPNative,
			Runtime: profile.RuntimeSpec{
				Timing:      profile.TimingInPath,
				Path:        profile.PathInPath,
				Composition: profile.CompositionKernloomOnly,
				Constraints: profile.RuntimeConstraints{
					RestrictiveOnly:   true,
					RequireTTL:        true,
					RequireAudit:      true,
					RequireLease:      true,
					RequireAutoRevert: true,
				},
			},
			AllowedRuntimeActions: []string{"network.rate_limit_source"},
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

func testKlshieldEnforcementPlan() *plan.EnforcementPlan {
	return &plan.EnforcementPlan{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "EnforcementPlan",
		Metadata: plan.PlanMetadata{
			Name:         "ziti-controller-klshield-local",
			SourcePolicy: "ziti-controller-admin-protection",
			Target:       "klshield-local",
			CompiledAt:   fixedNow(),
		},
		Spec: plan.EnforcementPlanSpec{
			Requirements: []plan.RequirementEnforcement{{
				ID:              "unknown-source-pressure",
				RequirementKind: "risk_level",
				Requirement:     "subject.risk.level == 'low'",
				Status:          plan.StatusCompensatingControl,
				ActionBinding: &plan.ActionBinding{
					Action:        "network.rate_limit_source",
					DecisionOwner: "kliq-runtime-pdp",
				},
			}},
			Summary: plan.PlanSummary{
				Deployable:           true,
				RuntimeModel:         "local_runtime_controlled",
				SemanticFidelity:     "medium",
				CompensatingControls: []string{"unknown-source-pressure"},
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

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
