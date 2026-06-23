// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntentConvertOutputDirEmitsPolicyIntent(t *testing.T) {
	dir := t.TempDir()
	cmd := intentConvertCmd()
	cmd.SetArgs([]string{
		"--input", filepath.Join("..", "..", "examples", "policies", "protect-ziti-controller.intent"),
		"--output-dir", dir,
		"--emit-policy-intent",
		"--owner", "security",
		"--compile-target", "klshield-local",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("intent convert: %v", err)
	}

	for _, name := range []string{
		"access.yaml",
		"requirements.yaml",
		"guardrails.yaml",
		"detections.yaml",
		"responses.yaml",
		"security-ops-alert-route.yaml",
		"capabilities.yaml",
		"policy-intent.yaml",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s: %v", name, err)
		}
	}

	comp, err := loadPolicyCompositionFromIntent(filepath.Join(dir, "policy-intent.yaml"), "")
	if err != nil {
		t.Fatalf("load generated PolicyIntent: %v", err)
	}
	if comp.AccessPolicy.Metadata.Name != "protect-ziti-controller-admin-access" {
		t.Fatalf("access policy name = %q", comp.AccessPolicy.Metadata.Name)
	}
	if comp.Intent.Spec.Compile.Target != "klshield-local" {
		t.Fatalf("compile target = %q", comp.Intent.Spec.Compile.Target)
	}
	if len(comp.Guardrails) != 3 {
		t.Fatalf("guardrails = %d", len(comp.Guardrails))
	}
	if len(comp.RequirementPolicies) != 1 {
		t.Fatalf("requirements = %d", len(comp.RequirementPolicies))
	}
	if len(comp.Intent.Spec.Documents.Requirements) != 1 {
		t.Fatalf("requirement refs = %#v", comp.Intent.Spec.Documents.Requirements)
	}
	if len(comp.DetectionRules) != 2 {
		t.Fatalf("detections = %d", len(comp.DetectionRules))
	}
	if len(comp.ResponseRules) != 2 {
		t.Fatalf("responses = %d", len(comp.ResponseRules))
	}
	if len(comp.AlertRoutes) != 1 || comp.AlertRoutes[0].ID != "alert-route.security-ops" {
		t.Fatalf("alert routes = %#v", comp.AlertRoutes)
	}
	if got := comp.Intent.Spec.Documents.AlertRoutes[0].Digest; !strings.HasPrefix(got, "sha256:") {
		t.Fatalf("alert route digest = %q", got)
	}
	if len(comp.Intent.Spec.Documents.CapabilityRequirements) != 1 {
		t.Fatalf("capability refs = %#v", comp.Intent.Spec.Documents.CapabilityRequirements)
	}
}

func TestIntentConvertOutputDirEmitsCapabilityRequirements(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "block.intent")
	if err := os.WriteFile(input, []byte(`
intent "block-example"
protect "ziti-controller"

access "ziti-controller-access":
  allow group "kernloom-admins" to access "ziti-controller"

requirements "low-risk":
  require "subject.risk.level" eq "low"

capabilities "ziti-controller-admin-protection":
  require context "subject.risk.level"
  require windowed_detection
  require traffic_rate_limit

gap_handling:
  fail on missing_context
`), 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "out")
	cmd := intentConvertCmd()
	cmd.SetArgs([]string{
		"--input", input,
		"--output-dir", outDir,
		"--emit-policy-intent",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("intent convert: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "capabilities.yaml")); err != nil {
		t.Fatalf("expected capabilities.yaml: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "requirements.yaml")); err != nil {
		t.Fatalf("expected requirements.yaml: %v", err)
	}
	comp, err := loadPolicyCompositionFromIntent(filepath.Join(outDir, "policy-intent.yaml"), "")
	if err != nil {
		t.Fatalf("load generated PolicyIntent: %v", err)
	}
	if len(comp.Intent.Spec.Documents.Requirements) != 1 {
		t.Fatalf("requirement refs = %#v", comp.Intent.Spec.Documents.Requirements)
	}
	if len(comp.Intent.Spec.Documents.CapabilityRequirements) != 1 {
		t.Fatalf("capability refs = %#v", comp.Intent.Spec.Documents.CapabilityRequirements)
	}
	if got := comp.Intent.Spec.Documents.CapabilityRequirements[0].Kind; got != "CapabilityRequirement" {
		t.Fatalf("capability ref kind = %q", got)
	}
}

func TestIntentConvertOutputDirCarriesRuntimeAutonomy(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "autonomy.intent")
	if err := os.WriteFile(input, []byte(`
intent "edge-autonomy"
protect service "public-edge"
allow all

autonomy "public-edge-runtime-autonomy":
  hold rate_limit source at 100 pps for 30s while enforcement feedback active
  step_down after clean 30s observe after 2m
  restore previous mitigation if pressure resumes during cooldown
  allow autonomous rate_limit for unknown sources
  allow autonomous temporary_block only after rate_limit was active
  require approval before identity disable
  never block more than 100 sources per tenant within 10m
  max autonomous block duration 15m
  require audit receipt for every enforcement
  max renewals 3
`), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := intentConvertCmd()
	cmd.SetArgs([]string{
		"--input", input,
		"--output-dir", dir,
		"--emit-policy-intent",
		"--compile-target", "klshield-local",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("intent convert: %v", err)
	}

	comp, err := loadPolicyCompositionFromIntent(filepath.Join(dir, "policy-intent.yaml"), "")
	if err != nil {
		t.Fatalf("load generated PolicyIntent: %v", err)
	}
	if comp.AutonomyLifecycle == nil || len(comp.AutonomyLifecycle.Hold) != 1 {
		t.Fatalf("autonomy lifecycle = %#v", comp.AutonomyLifecycle)
	}
	if got := comp.AutonomyLifecycle.Hold[0].Action.Params["rate_pps"]; got != 100 {
		t.Fatalf("rate_pps = %#v", got)
	}
	if len(comp.AutonomyLifecycle.Allow) != 2 || !comp.AutonomyLifecycle.RequiresAudit {
		t.Fatalf("autonomy bounds = %#v", comp.AutonomyLifecycle)
	}
}

func TestIntentSupportReportsRuntimeSupportStatus(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "support.intent")
	output := filepath.Join(dir, "support.yaml")
	if err := os.WriteFile(input, []byte(`
intent "edge-support"
protect service "public-edge"
allow all

response "edge-responses":
  on "risk-elevated" then rate_limit source for 1m with escalation soft_to_hard

autonomy "edge-autonomy":
  hold rate_limit source at 100 pps for 30s while enforcement feedback active
  step_down after clean 30s observe after 2m
`), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := intentSupportCmd()
	cmd.SetArgs([]string{
		"--input", input,
		"--target", "klshield-local",
		"--output", output,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("intent support: %v", err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read support report: %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		"kind: NaturalIntentSupportReport",
		"target: klshield-local",
		"enforced:",
		"carried:",
		"warnings:",
		"status: enforced",
		"status: carried",
		"status: warning",
		"response escalation",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("support report missing %q:\n%s", want, text)
		}
	}
}
