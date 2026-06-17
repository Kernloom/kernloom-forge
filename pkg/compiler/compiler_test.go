// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package compiler_test

import (
	"testing"

	"github.com/kernloom/kernloom-forge/pkg/compiler"
	"github.com/kernloom/kernloom-forge/pkg/core/action"
	"github.com/kernloom/kernloom-forge/pkg/core/adapter"
	"github.com/kernloom/kernloom-forge/pkg/core/intent"
	"github.com/kernloom/kernloom-forge/pkg/core/mapping"
	"github.com/kernloom/kernloom-forge/pkg/core/plan"
	"github.com/kernloom/kernloom-forge/pkg/core/profile"
	"github.com/kernloom/kernloom-forge/pkg/core/requirement"
)

// TestGoldenInvestorApps is the canonical MVP acceptance test:
//
//	investors may access investor-apps only with MFA, low risk and healthy device
//
// Targets:
//   - openziti-production (enterprise_risk_overlay):
//     subject/resource=implemented, auth=delegated, risk=compensating_control, posture=partial
//     → deployable
//   - openziti-config-only (config_only, no runtime actions):
//     risk_level mapping is partial (posture-as-proxy), not compensating_control
//     → deployable
//   - idp-production (config_only):
//     subject/resource/auth=full, risk/posture=partial → deployable
//   - klshield-local (kernloom_pdp_native):
//     auth=unsupported → NOT deployable
func TestGoldenInvestorApps(t *testing.T) {
	policy := investorAppsPolicy()
	reqs, err := requirement.Extract(policy)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	profiles := []*profile.TargetIntegrationProfile{
		openzitiProductionProfile(),
		openzitiConfigOnlyProfile(),
		idpProductionProfile(),
		klshieldLocalProfile(),
	}

	bundles := map[string]*compiler.TargetBundle{
		"openziti": openzitiBundle(),
		"idp":      idpBundle(),
		"klshield": klshieldBundle(),
	}

	plans := compiler.Compile(policy.Metadata.Name, reqs, profiles, bundles)

	// Find plans by target name.
	find := func(target string) *plan.EnforcementPlan {
		for _, p := range plans {
			if p.Metadata.Target == target {
				return p
			}
		}
		t.Fatalf("no plan for target %q", target)
		return nil
	}

	// ── openziti-production ──────────────────────────────────────────────────
	oz := find("openziti-production")
	assertDeployable(t, oz, true)
	assertRequirementStatus(t, oz, "require-mfa", plan.StatusDelegated)
	assertRequirementStatus(t, oz, "require-low-risk", plan.StatusCompensatingControl)
	assertRequirementStatus(t, oz, "require-healthy-device", plan.StatusPartial)
	assertRequirementStatus(t, oz, "subject-identity", plan.StatusImplemented)
	assertRequirementStatus(t, oz, "resource-identity", plan.StatusImplemented)

	// Compensating control binding must reference the correct action and attribute.
	riskEntry := findRequirement(t, oz, "require-low-risk")
	if riskEntry.ActionBinding == nil {
		t.Error("require-low-risk: ActionBinding must not be nil")
	} else {
		if riskEntry.ActionBinding.Action != "remove_kernloom_access_attribute" {
			t.Errorf("risk ActionBinding.Action = %q, want remove_kernloom_access_attribute",
				riskEntry.ActionBinding.Action)
		}
		if riskEntry.ActionBinding.Attribute != "kl.access.active" {
			t.Errorf("risk ActionBinding.Attribute = %q, want kl.access.active",
				riskEntry.ActionBinding.Attribute)
		}
	}

	// ── openziti-config-only ─────────────────────────────────────────────────
	// No runtime actions allowed in this profile. The mapping declares risk_level
	// as compensating_control, but the profile's empty allowedRuntimeActions causes
	// the compiler to mark it unsupported → not deployable. This is correct: a
	// config-only OpenZiti deployment cannot enforce enterprise risk.
	ozco := find("openziti-config-only")
	assertDeployable(t, ozco, false)
	assertRequirementStatus(t, ozco, "require-low-risk", plan.StatusUnsupported)

	// ── idp-production ────────────────────────────────────────────────────────
	idp := find("idp-production")
	assertDeployable(t, idp, true)
	assertRequirementStatus(t, idp, "require-mfa", plan.StatusImplemented)
	assertRequirementStatus(t, idp, "require-low-risk", plan.StatusPartial)
	assertRequirementStatus(t, idp, "require-healthy-device", plan.StatusPartial)

	// ── klshield-local ────────────────────────────────────────────────────────
	ks := find("klshield-local")
	// auth_strength is unsupported → not deployable for this policy.
	assertDeployable(t, ks, false)
	assertRequirementStatus(t, ks, "require-mfa", plan.StatusUnsupported)
	assertRequirementStatus(t, ks, "require-low-risk", plan.StatusCompensatingControl)
	assertRequirementStatus(t, ks, "require-healthy-device", plan.StatusCompensatingControl)

	// No requirements silently dropped — all appear in every plan.
	allReqs := reqs.All()
	for _, p := range plans {
		if len(p.Spec.Requirements) != len(allReqs) {
			t.Errorf("plan %s: expected %d requirements, got %d",
				p.Metadata.Target, len(allReqs), len(p.Spec.Requirements))
		}
	}
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

func investorAppsPolicy() *intent.AccessPolicy {
	return &intent.AccessPolicy{
		APIVersion: "kernloom.io/v1",
		Kind:       intent.KindAccessPolicy,
		Metadata:   intent.PolicyMetadata{Name: "investor-apps-access"},
		Spec: intent.AccessPolicySpec{
			Subject:  intent.Subject{Type: "role", Ref: "investors"},
			Action:   "access",
			Resource: intent.Resource{Type: "application_group", Ref: "investor-apps"},
			Effect:   "allow",
			Conditions: []intent.Condition{
				{ID: "require-mfa", Type: "authentication_strength",
					Signal: "subject.auth_strength", Operator: "gte", Value: "mfa"},
				{ID: "require-low-risk", Type: "risk_level",
					Signal: "subject.risk.level", Operator: "eq", Value: "low"},
				{ID: "require-healthy-device", Type: "device_posture",
					Signal: "device.posture.status", Operator: "eq", Value: "healthy"},
			},
		},
	}
}

func openzitiProductionProfile() *profile.TargetIntegrationProfile {
	return &profile.TargetIntegrationProfile{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "TargetIntegrationProfile",
		Metadata:   profile.ProfileMetadata{Name: "openziti-production"},
		Spec: profile.ProfileSpec{
			AdapterRef: "openziti",
			Mode:       profile.ModeEnterpriseRiskOverlay,
			Ownership: profile.ProfileOwnership{
				EnterpriseControlDecision:   profile.ProfileOwner{Owner: "kernloom-runtime-pdp"},
				TargetAuthorizationDecision: profile.ProfileOwner{Owner: "openziti-controller"},
				TargetPolicyEvaluation:      profile.ProfileOwner{Owner: "openziti-controller"},
				Enforcement:                 profile.ProfileOwner{Owner: "openziti-edge-router"},
			},
			AllowedRuntimeActions: []string{
				"remove_kernloom_access_attribute",
				"identity.disable",
			},
		},
	}
}

func openzitiConfigOnlyProfile() *profile.TargetIntegrationProfile {
	return &profile.TargetIntegrationProfile{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "TargetIntegrationProfile",
		Metadata:   profile.ProfileMetadata{Name: "openziti-config-only"},
		Spec: profile.ProfileSpec{
			AdapterRef:            "openziti",
			Mode:                  profile.ModeConfigOnly,
			AllowedRuntimeActions: []string{}, // no runtime actions
		},
	}
}

func idpProductionProfile() *profile.TargetIntegrationProfile {
	return &profile.TargetIntegrationProfile{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "TargetIntegrationProfile",
		Metadata:   profile.ProfileMetadata{Name: "idp-production"},
		Spec: profile.ProfileSpec{
			AdapterRef:            "idp",
			Mode:                  profile.ModeConfigOnly,
			AllowedRuntimeActions: []string{},
		},
	}
}

func klshieldLocalProfile() *profile.TargetIntegrationProfile {
	return &profile.TargetIntegrationProfile{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "TargetIntegrationProfile",
		Metadata:   profile.ProfileMetadata{Name: "klshield-local"},
		Spec: profile.ProfileSpec{
			AdapterRef: "klshield",
			Mode:       profile.ModeKernloomPDPNative,
			AllowedRuntimeActions: []string{
				"network.flow_deny",
				"network.flow_rate_limit",
				"network.cgroup_block",
			},
		},
	}
}

func openzitiBundle() *compiler.TargetBundle {
	return &compiler.TargetBundle{
		Adapter: &adapter.AdapterCapabilityManifest{
			APIVersion: "kernloom.io/v1alpha1",
			Kind:       "AdapterCapabilityManifest",
			Metadata:   adapter.AdapterMetadata{Name: "openziti"},
			Spec: adapter.AdapterSpec{
				TargetType: adapter.TargetTypeVendorSubControlPlane,
			},
		},
		Mappings: &mapping.RequirementMappingSet{
			APIVersion: "kernloom.io/v1alpha1",
			Kind:       "RequirementMappingSet",
			Metadata:   mapping.MappingMetadata{Name: "openziti-mappings", AdapterRef: "openziti"},
			Spec: mapping.MappingSetSpec{
				Mappings: []mapping.MappingEntry{
					{Requirement: mapping.RequirementRef{Kind: "subject_identity"},
						Capability: mapping.CapabilityRef{ID: "identity.role_attributes"},
						Support: mapping.SupportFull, Fidelity: mapping.FidelityHigh},
					{Requirement: mapping.RequirementRef{Kind: "resource_identity"},
						Capability: mapping.CapabilityRef{ID: "resource.service_definition"},
						Support: mapping.SupportFull, Fidelity: mapping.FidelityHigh},
					{Requirement: mapping.RequirementRef{Kind: "auth_strength"},
						Capability: mapping.CapabilityRef{ID: "authentication.mfa_posture"},
						Support: mapping.SupportDelegated, Fidelity: mapping.FidelityMedium,
						Delegation: &mapping.DelegationSpec{EvaluationOwner: "openziti-controller"}},
					{Requirement: mapping.RequirementRef{Kind: "risk_level"},
						Support: mapping.SupportCompensatingControl, Fidelity: mapping.FidelityMedium,
						Binding: &mapping.CompensatingBinding{
							RiskAssessmentOwner: "kernloom-risk-engine",
							DecisionOwner:       "kernloom-runtime-pdp",
							Action:              "remove_kernloom_access_attribute",
							Attribute:           "kl.access.active",
						}},
					{Requirement: mapping.RequirementRef{Kind: "device_posture"},
						Capability: mapping.CapabilityRef{ID: "device.posture_check"},
						Support: mapping.SupportPartial, Fidelity: mapping.FidelityMedium,
						Downgrade: &mapping.DowngradeNote{
							From:   "Enterprise posture with EDR signals",
							To:     "OpenZiti posture check: binary pass/fail",
							Reason: "OpenZiti posture checks are binary and static",
						}},
					{Requirement: mapping.RequirementRef{Kind: "session_context"},
						Support: mapping.SupportUnsupported},
					{Requirement: mapping.RequirementRef{Kind: "network_tuple"},
						Support: mapping.SupportUnsupported},
					{Requirement: mapping.RequirementRef{Kind: "custom"},
						Support: mapping.SupportUnsupported},
				},
			},
		},
		Catalog: &action.RuntimeActionCatalog{
			APIVersion: "kernloom.io/v1alpha1",
			Kind:       "RuntimeActionCatalog",
			Metadata:   action.CatalogMetadata{Name: "openziti-actions", AdapterRef: "openziti"},
			Spec: action.CatalogSpec{
				Actions: []action.ActionEntry{
					{
						ID:     "remove_kernloom_access_attribute",
						Effect: action.EffectRestrictive,
						Scope:  "role_attribute",
						Requirements: action.ActionRequirements{
							TTL: action.LevelRequired, Lease: action.LevelRequired,
						},
						RevertStrategy: action.RevertStrategy{
							Type: action.RevertCompareAndRestore, RequireFencingToken: true,
						},
						ConflictPolicy: action.ConflictPolicy{
							Type: action.ConflictStrongestRestrictionWins,
						},
					},
					{
						ID:     "identity.disable",
						Effect: action.EffectRestrictive,
						Scope:  "identity",
						Requirements: action.ActionRequirements{
							TTL: action.LevelRequired, Lease: action.LevelRequired,
						},
						RevertStrategy: action.RevertStrategy{
							Type: action.RevertRestorePreviousState,
						},
						ConflictPolicy: action.ConflictPolicy{
							Type: action.ConflictStrongestRestrictionWins,
						},
					},
				},
			},
		},
	}
}

func idpBundle() *compiler.TargetBundle {
	return &compiler.TargetBundle{
		Adapter: &adapter.AdapterCapabilityManifest{
			APIVersion: "kernloom.io/v1alpha1",
			Kind:       "AdapterCapabilityManifest",
			Metadata:   adapter.AdapterMetadata{Name: "idp"},
			Spec:       adapter.AdapterSpec{TargetType: adapter.TargetTypeIdentitySystem},
		},
		Mappings: &mapping.RequirementMappingSet{
			APIVersion: "kernloom.io/v1alpha1",
			Kind:       "RequirementMappingSet",
			Metadata:   mapping.MappingMetadata{Name: "idp-mappings", AdapterRef: "idp"},
			Spec: mapping.MappingSetSpec{
				Mappings: []mapping.MappingEntry{
					{Requirement: mapping.RequirementRef{Kind: "subject_identity"},
						Capability: mapping.CapabilityRef{ID: "identity.group_membership"},
						Support: mapping.SupportFull, Fidelity: mapping.FidelityHigh},
					{Requirement: mapping.RequirementRef{Kind: "resource_identity"},
						Capability: mapping.CapabilityRef{ID: "resource.app_assignment"},
						Support: mapping.SupportFull, Fidelity: mapping.FidelityHigh},
					{Requirement: mapping.RequirementRef{Kind: "auth_strength"},
						Capability: mapping.CapabilityRef{ID: "authentication.mfa"},
						Support: mapping.SupportFull, Fidelity: mapping.FidelityHigh},
					{Requirement: mapping.RequirementRef{Kind: "risk_level"},
						Capability: mapping.CapabilityRef{ID: "risk.sign_in_risk"},
						Support: mapping.SupportPartial, Fidelity: mapping.FidelityMedium,
						Downgrade: &mapping.DowngradeNote{
							From:   "Enterprise continuous risk score",
							To:     "IdP sign-in risk at authentication time only",
							Reason: "IdP risk evaluated at sign-in only",
						}},
					{Requirement: mapping.RequirementRef{Kind: "device_posture"},
						Capability: mapping.CapabilityRef{ID: "device.mdm_compliance"},
						Support: mapping.SupportPartial, Fidelity: mapping.FidelityMedium,
						Downgrade: &mapping.DowngradeNote{
							From:   "Enterprise posture: healthy (EDR + patch + encryption + drift)",
							To:     "IdP device compliance: MDM-reported compliant status",
							Reason: "IdP compliance reflects MDM status only",
						}},
					{Requirement: mapping.RequirementRef{Kind: "session_context"},
						Capability: mapping.CapabilityRef{ID: "session.location_policy"},
						Support: mapping.SupportFull, Fidelity: mapping.FidelityHigh},
					{Requirement: mapping.RequirementRef{Kind: "network_tuple"},
						Support: mapping.SupportUnsupported},
					{Requirement: mapping.RequirementRef{Kind: "custom"},
						Support: mapping.SupportUnsupported},
				},
			},
		},
	}
}

func klshieldBundle() *compiler.TargetBundle {
	return &compiler.TargetBundle{
		Adapter: &adapter.AdapterCapabilityManifest{
			APIVersion: "kernloom.io/v1alpha1",
			Kind:       "AdapterCapabilityManifest",
			Metadata:   adapter.AdapterMetadata{Name: "klshield"},
			Spec:       adapter.AdapterSpec{TargetType: adapter.TargetTypeLocalPEP},
		},
		Mappings: &mapping.RequirementMappingSet{
			APIVersion: "kernloom.io/v1alpha1",
			Kind:       "RequirementMappingSet",
			Metadata:   mapping.MappingMetadata{Name: "klshield-mappings", AdapterRef: "klshield"},
			Spec: mapping.MappingSetSpec{
				Mappings: []mapping.MappingEntry{
					{Requirement: mapping.RequirementRef{Kind: "subject_identity"},
						Capability: mapping.CapabilityRef{ID: "identity.process_cgroup"},
						Support: mapping.SupportPartial, Fidelity: mapping.FidelityLow,
						Downgrade: &mapping.DowngradeNote{
							From: "Enterprise role identity", To: "Local process/cgroup identity",
							Reason: "eBPF tracks local processes; enterprise roles require IdP"}},
					{Requirement: mapping.RequirementRef{Kind: "resource_identity"},
						Capability: mapping.CapabilityRef{ID: "network.flow_control"},
						Support: mapping.SupportPartial, Fidelity: mapping.FidelityMedium,
						Downgrade: &mapping.DowngradeNote{
							From: "Enterprise application_group", To: "IP/port set",
							Reason: "KLShield resolves resources to network tuples only"}},
					{Requirement: mapping.RequirementRef{Kind: "auth_strength"},
						Support: mapping.SupportUnsupported},
					{Requirement: mapping.RequirementRef{Kind: "risk_level"},
						Capability: mapping.CapabilityRef{ID: "network.flow_deny"},
						Support: mapping.SupportCompensatingControl, Fidelity: mapping.FidelityHigh,
						Binding: &mapping.CompensatingBinding{
							RiskAssessmentOwner: "kernloom-risk-engine",
							DecisionOwner:       "kernloom-runtime-pdp",
							Action:              "network.flow_deny",
						}},
					{Requirement: mapping.RequirementRef{Kind: "device_posture"},
						Capability: mapping.CapabilityRef{ID: "network.flow_deny"},
						Support: mapping.SupportCompensatingControl, Fidelity: mapping.FidelityHigh,
						Binding: &mapping.CompensatingBinding{
							RiskAssessmentOwner: "kernloom-risk-engine",
							DecisionOwner:       "kernloom-runtime-pdp",
							Action:              "network.flow_deny",
						}},
					{Requirement: mapping.RequirementRef{Kind: "session_context"},
						Support: mapping.SupportUnsupported},
					{Requirement: mapping.RequirementRef{Kind: "network_tuple"},
						Capability: mapping.CapabilityRef{ID: "network.flow_control"},
						Support: mapping.SupportFull, Fidelity: mapping.FidelityHigh},
					{Requirement: mapping.RequirementRef{Kind: "custom"},
						Support: mapping.SupportUnsupported},
				},
			},
		},
		Catalog: &action.RuntimeActionCatalog{
			APIVersion: "kernloom.io/v1alpha1",
			Kind:       "RuntimeActionCatalog",
			Metadata:   action.CatalogMetadata{Name: "klshield-actions", AdapterRef: "klshield"},
			Spec: action.CatalogSpec{
				Actions: []action.ActionEntry{
					{ID: "network.flow_deny", Effect: action.EffectRestrictive, Scope: "flow",
						Requirements: action.ActionRequirements{TTL: action.LevelRequired},
						RevertStrategy: action.RevertStrategy{Type: action.RevertRestorePreviousState},
						ConflictPolicy: action.ConflictPolicy{Type: action.ConflictStrongestRestrictionWins}},
					{ID: "network.flow_rate_limit", Effect: action.EffectRestrictive, Scope: "flow",
						Requirements: action.ActionRequirements{TTL: action.LevelRequired},
						RevertStrategy: action.RevertStrategy{Type: action.RevertRestorePreviousState},
						ConflictPolicy: action.ConflictPolicy{Type: action.ConflictStrongestRestrictionWins}},
					{ID: "network.cgroup_block", Effect: action.EffectRestrictive, Scope: "cgroup",
						Requirements: action.ActionRequirements{TTL: action.LevelRequired},
						RevertStrategy: action.RevertStrategy{Type: action.RevertRestorePreviousState},
						ConflictPolicy: action.ConflictPolicy{Type: action.ConflictStrongestRestrictionWins}},
				},
			},
		},
	}
}

// ── Assertion helpers ────────────────────────────────────────────────────────

func assertDeployable(t *testing.T, p *plan.EnforcementPlan, want bool) {
	t.Helper()
	if p.Spec.Summary.Deployable != want {
		t.Errorf("plan %s: deployable = %v, want %v (unsupported: %v)",
			p.Metadata.Target, p.Spec.Summary.Deployable, want, p.Spec.Summary.Unsupported)
	}
}

func assertRequirementStatus(t *testing.T, p *plan.EnforcementPlan, reqID string, want plan.RequirementStatus) {
	t.Helper()
	for _, r := range p.Spec.Requirements {
		if r.ID == reqID {
			if r.Status != want {
				t.Errorf("plan %s requirement %q: status = %q, want %q",
					p.Metadata.Target, reqID, r.Status, want)
			}
			return
		}
	}
	t.Errorf("plan %s: requirement %q not found", p.Metadata.Target, reqID)
}

func findRequirement(t *testing.T, p *plan.EnforcementPlan, reqID string) plan.RequirementEnforcement {
	t.Helper()
	for _, r := range p.Spec.Requirements {
		if r.ID == reqID {
			return r
		}
	}
	t.Fatalf("plan %s: requirement %q not found", p.Metadata.Target, reqID)
	return plan.RequirementEnforcement{}
}
