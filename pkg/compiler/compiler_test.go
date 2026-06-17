// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package compiler_test

import (
	"testing"

	"github.com/kernloom/kernloom-forge/pkg/compiler"
	"github.com/kernloom/kernloom-forge/pkg/core/capability"
	"github.com/kernloom/kernloom-forge/pkg/core/intent"
	"github.com/kernloom/kernloom-forge/pkg/core/report"
	"github.com/kernloom/kernloom-forge/pkg/core/requirement"
)

// sharedPolicy returns the canonical golden test policy:
//
//	investors may access investor-apps only with MFA, low risk and healthy device
func sharedPolicy() *intent.AccessPolicy {
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

// openzitiVariantB returns an OpenZiti manifest for Variant B:
// Kernloom runtime PDP decides, OpenZiti enforces.
// risk_level is covered via runtime_action (Action Broker → OpenZiti identity ops).
func openzitiVariantB() *capability.CapabilityManifest {
	return &capability.CapabilityManifest{
		APIVersion: "kernloom.io/v1",
		Kind:       "CapabilityManifest",
		Metadata:   capability.ManifestMetadata{Name: "openziti"},
		Spec: capability.ManifestSpec{
			TargetType:      capability.TargetTypeVendorSubControlPlane,
			IntegrationMode: capability.IntegrationModeHybridOutOfBand,
			RuntimeOwner:    "kernloom-runtime-pdp",
			ConfigOwner:     "kernloom",
			Ownership: &capability.OwnershipDeclaration{
				IntentOwner:           "enterprise-pms",
				RuntimeContextOwner:   "kernloom-pips",
				RiskDecisionOwner:     "kernloom-runtime-pdp",
				RuntimeDecisionOwner:  "kernloom-runtime-pdp",
				RuntimeStateOwner:     "openziti",
				PolicyEvaluationOwner: "openziti",
				EnforcementOwner:      "openziti",
				ConfigOwner:           "kernloom",
			},
			RequirementCoverage: map[string]capability.CoverageLevel{
				"subject_identity":  capability.CoverageFull,
				"resource_identity": capability.CoverageFull,
				"auth_strength":     capability.CoverageDelegated,
				"risk_level":        capability.CoverageRuntimeAction,
				"device_posture":    capability.CoveragePartial,
				"session_context":   capability.CoverageUnsupported,
				"network_tuple":     capability.CoverageUnsupported,
				"custom":            capability.CoverageUnsupported,
			},
			DelegationNotes: map[string]string{
				"auth_strength": "MFA enforced by OpenZiti controller MFA posture check",
			},
			Downgrades: []capability.DowngradeDeclaration{
				{
					Requirement: "device_posture",
					From:        "Enterprise posture: healthy/unhealthy/unknown with EDR signals",
					To:          "OpenZiti posture check: pass/fail on configured criteria",
					Reason:      "OpenZiti posture checks are binary; continuous EDR signals not consumed",
				},
			},
			RuntimeActions: []capability.RuntimeActionDeclaration{
				{Action: "disable_identity", Scope: "identity",
					RequiresTTL: true, AutoRevert: true},
				{Action: "set_role_attribute", Scope: "role_attribute",
					RequiresTTL: true, AutoRevert: true},
				{Action: "remove_role_attribute", Scope: "role_attribute",
					RequiresTTL: true, AutoRevert: true},
				{Action: "activate_quarantine_service_policy", Scope: "service_policy",
					RequiresTTL: true, AutoRevert: true},
			},
		},
	}
}

// openzitiVariantA returns an OpenZiti manifest for Variant A:
// runtime fully delegated to OpenZiti — config-only, no Kernloom runtime PDP.
func openzitiVariantA() *capability.CapabilityManifest {
	return &capability.CapabilityManifest{
		APIVersion: "kernloom.io/v1",
		Kind:       "CapabilityManifest",
		Metadata:   capability.ManifestMetadata{Name: "openziti"},
		Spec: capability.ManifestSpec{
			TargetType:      capability.TargetTypeVendorSubControlPlane,
			IntegrationMode: capability.IntegrationModeConfigOnly,
			RuntimeOwner:    "vendor",
			ConfigOwner:     "kernloom",
			Ownership: &capability.OwnershipDeclaration{
				IntentOwner:           "enterprise-pms",
				RuntimeContextOwner:   capability.OwnerVendor,
				RiskDecisionOwner:     capability.OwnerVendor,
				RuntimeDecisionOwner:  capability.OwnerVendor,
				PolicyEvaluationOwner: capability.OwnerVendor,
				EnforcementOwner:      capability.OwnerVendor,
				ConfigOwner:           capability.OwnerKernloom,
			},
			RequirementCoverage: map[string]capability.CoverageLevel{
				"subject_identity":  capability.CoverageFull,
				"resource_identity": capability.CoverageFull,
				"auth_strength":     capability.CoverageDelegated,
				"risk_level":        capability.CoverageDelegated, // OpenZiti posture as proxy
				"device_posture":    capability.CoveragePartial,
				"session_context":   capability.CoverageUnsupported,
				"network_tuple":     capability.CoverageUnsupported,
				"custom":            capability.CoverageUnsupported,
			},
			DelegationNotes: map[string]string{
				"auth_strength": "MFA enforced by OpenZiti controller MFA posture check",
				"risk_level":    "Delegated to OpenZiti posture checks as structural proxy; enterprise EDR signals not consumed",
			},
			Downgrades: []capability.DowngradeDeclaration{
				{
					Requirement: "device_posture",
					From:        "Enterprise posture: healthy/unhealthy/unknown with EDR signals",
					To:          "OpenZiti posture check: pass/fail on configured criteria",
					Reason:      "OpenZiti posture checks are binary; continuous EDR signals not consumed",
				},
			},
		},
	}
}

// TestGoldenInvestorApps_VariantB tests Variant B: Kernloom runtime PDP + OpenZiti enforcement.
//
// Expected outcomes:
//   - openziti: deployable — risk_level via runtime_action, auth delegated, posture partial
//   - idp:      deployable — full on subject/resource/auth, partial on risk/device
//   - netfilter: partial   — identity/auth/risk/posture unsupported; only resource partial
func TestGoldenInvestorApps_VariantB(t *testing.T) {
	policy := sharedPolicy()
	reqs, err := requirement.Extract(policy)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	idpManifest := idpTestManifest()
	netfilterManifest := netfilterTestManifest()

	targets := []compiler.TargetInput{
		{Manifest: openzitiVariantB()},
		{Manifest: idpManifest},
		{Manifest: netfilterManifest},
	}

	reports := compiler.Compile(policy.Metadata.Name, reqs, targets)

	// OpenZiti Variant B: deployable because risk_level is runtime_action (not a gap)
	assertTargetStatus(t, reports, "openziti", report.TargetStatusDeployable)
	assertTargetStatus(t, reports, "idp", report.TargetStatusDeployable)
	assertTargetStatus(t, reports, "netfilter", report.TargetStatusPartial)

	// Delegation: auth_strength delegated to OpenZiti
	assertDelegationExists(t, reports, "require-mfa", "openziti")

	// Downgrades: device_posture on OpenZiti and IdP; risk_level on IdP
	assertDowngradeExists(t, reports, "require-healthy-device", "openziti")
	assertDowngradeExists(t, reports, "require-healthy-device", "idp")
	assertDowngradeExists(t, reports, "require-low-risk", "idp")
	assertDowngradeExists(t, reports, "resource-identity", "netfilter")

	// RuntimeActionPlan: risk_level covered via Action Broker on OpenZiti
	assertRuntimeActionExists(t, reports, "require-low-risk", "openziti")

	// The runtime action entry should reference Kernloom as decision owner
	for _, e := range reports.RuntimeActions.Entries {
		if e.RequirementID == "require-low-risk" && e.TargetName == "openziti" {
			if e.RuntimeDecisionOwner != "kernloom-runtime-pdp" {
				t.Errorf("runtime action: RuntimeDecisionOwner = %q, want kernloom-runtime-pdp", e.RuntimeDecisionOwner)
			}
			if e.RuntimeStateOwner != "openziti" {
				t.Errorf("runtime action: RuntimeStateOwner = %q, want openziti", e.RuntimeStateOwner)
			}
			if len(e.AvailableActions) == 0 {
				t.Error("runtime action: AvailableActions must not be empty")
			}
			break
		}
	}

	// No requirements silently dropped
	assertAllRequirementsPresent(t, reports, reqs, targets)
}

// TestGoldenInvestorApps_VariantA tests Variant A: runtime fully delegated to OpenZiti.
//
// Expected outcomes:
//   - openziti: deployable — all requirements delegated or partial (no Kernloom runtime PDP)
//   - risk_level is delegated, not runtime_action
//   - no RuntimeActionPlan entries for OpenZiti
func TestGoldenInvestorApps_VariantA(t *testing.T) {
	policy := sharedPolicy()
	reqs, err := requirement.Extract(policy)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	targets := []compiler.TargetInput{
		{Manifest: openzitiVariantA()},
	}

	reports := compiler.Compile(policy.Metadata.Name, reqs, targets)

	// Variant A: deployable (risk_level is delegated, not unsupported)
	assertTargetStatus(t, reports, "openziti", report.TargetStatusDeployable)

	// risk_level and auth_strength are both delegated to OpenZiti
	assertDelegationExists(t, reports, "require-mfa", "openziti")
	assertDelegationExists(t, reports, "require-low-risk", "openziti")

	// No runtime action entries — this is config-only
	for _, e := range reports.RuntimeActions.Entries {
		if e.TargetName == "openziti" {
			t.Errorf("Variant A should have no runtime action entries for openziti, got: %+v", e)
		}
	}
}

// ── Shared manifests ─────────────────────────────────────────────────────────

func idpTestManifest() *capability.CapabilityManifest {
	return &capability.CapabilityManifest{
		APIVersion: "kernloom.io/v1",
		Kind:       "CapabilityManifest",
		Metadata:   capability.ManifestMetadata{Name: "idp"},
		Spec: capability.ManifestSpec{
			TargetType:      capability.TargetTypeIdentitySystem,
			IntegrationMode: capability.IntegrationModeConfigOnly,
			RuntimeOwner:    "vendor",
			ConfigOwner:     "kernloom",
			RequirementCoverage: map[string]capability.CoverageLevel{
				"subject_identity":  capability.CoverageFull,
				"resource_identity": capability.CoverageFull,
				"auth_strength":     capability.CoverageFull,
				"risk_level":        capability.CoveragePartial,
				"device_posture":    capability.CoveragePartial,
				"session_context":   capability.CoverageFull,
				"network_tuple":     capability.CoverageUnsupported,
				"custom":            capability.CoverageUnsupported,
			},
			Downgrades: []capability.DowngradeDeclaration{
				{Requirement: "risk_level",
					From:   "Enterprise risk: continuous EDR/SIEM composite score",
					To:     "IdP sign-in risk: authentication-time signal only",
					Reason: "IdP risk is evaluated at sign-in only"},
				{Requirement: "device_posture",
					From:   "Enterprise posture: healthy (EDR + patch + encryption + drift)",
					To:     "IdP device compliance: MDM-reported compliant status",
					Reason: "IdP compliance reflects MDM status only"},
			},
		},
	}
}

func netfilterTestManifest() *capability.CapabilityManifest {
	return &capability.CapabilityManifest{
		APIVersion: "kernloom.io/v1",
		Kind:       "CapabilityManifest",
		Metadata:   capability.ManifestMetadata{Name: "netfilter"},
		Spec: capability.ManifestSpec{
			TargetType:      capability.TargetTypeLocalPEP,
			IntegrationMode: capability.IntegrationModeConfigOnly,
			RuntimeOwner:    "kernloom",
			ConfigOwner:     "kernloom",
			RequirementCoverage: map[string]capability.CoverageLevel{
				"subject_identity":  capability.CoverageUnsupported,
				"resource_identity": capability.CoveragePartial,
				"auth_strength":     capability.CoverageUnsupported,
				"risk_level":        capability.CoverageUnsupported,
				"device_posture":    capability.CoverageUnsupported,
				"session_context":   capability.CoverageUnsupported,
				"network_tuple":     capability.CoverageFull,
				"custom":            capability.CoverageUnsupported,
			},
			Downgrades: []capability.DowngradeDeclaration{
				{Requirement: "resource_identity",
					From:   "application_group investor-apps (enterprise semantic grouping)",
					To:     "nftables IP/port set manually compiled from service inventory",
					Reason: "netfilter has no application-group concept"},
			},
		},
	}
}

// ── Assertion helpers ────────────────────────────────────────────────────────

func assertTargetStatus(t *testing.T, reports *report.CompileReports, target string, want report.TargetStatus) {
	t.Helper()
	tc := reports.Coverage.TargetFor(target)
	if tc == nil {
		t.Fatalf("no coverage for target %q", target)
	}
	if tc.Status != want {
		t.Errorf("target %q: status = %q, want %q", target, tc.Status, want)
		for _, r := range tc.Requirements {
			t.Logf("  %s (%s): %s", r.RequirementID, r.RequirementKind, r.Coverage)
		}
	}
}

func assertDelegationExists(t *testing.T, reports *report.CompileReports, reqID, targetName string) {
	t.Helper()
	for _, d := range reports.Delegation.Delegations {
		if d.RequirementID == reqID && d.DelegatedTo == targetName {
			return
		}
	}
	t.Errorf("expected delegation for requirement %q to target %q — not found", reqID, targetName)
}

func assertDowngradeExists(t *testing.T, reports *report.CompileReports, reqID, targetName string) {
	t.Helper()
	for _, d := range reports.Downgrade.Downgrades {
		if d.RequirementID == reqID && d.TargetName == targetName {
			return
		}
	}
	t.Errorf("expected semantic downgrade for requirement %q on target %q — not found", reqID, targetName)
}

func assertRuntimeActionExists(t *testing.T, reports *report.CompileReports, reqID, targetName string) {
	t.Helper()
	for _, e := range reports.RuntimeActions.Entries {
		if e.RequirementID == reqID && e.TargetName == targetName {
			return
		}
	}
	t.Errorf("expected runtime action entry for requirement %q on target %q — not found", reqID, targetName)
}

func assertAllRequirementsPresent(t *testing.T, reports *report.CompileReports, reqs *requirement.RequirementSet, targets []compiler.TargetInput) {
	t.Helper()
	allReqs := reqs.All()
	for _, ti := range targets {
		tc := reports.Coverage.TargetFor(ti.Manifest.Metadata.Name)
		if tc == nil {
			t.Fatalf("missing target coverage for %s", ti.Manifest.Metadata.Name)
		}
		if len(tc.Requirements) != len(allReqs) {
			t.Errorf("target %s: expected %d requirement rows, got %d",
				ti.Manifest.Metadata.Name, len(allReqs), len(tc.Requirements))
		}
	}
}
