// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kernloom/kernloom-forge/pkg/bundler"
)

func TestDocAcceptanceManualEdgeNaturalIntentToRuntimePolicyPack(t *testing.T) {
	dir := t.TempDir()
	cmd := intentConvertCmd()
	cmd.SetArgs([]string{
		"--input", filepath.Join("..", "..", "examples", "policies", "manual-edge-access.intent"),
		"--output-dir", dir,
		"--emit-policy-intent",
		"--compile-target", "klshield-local",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("intent convert: %v", err)
	}

	intentPath := filepath.Join(dir, "policy-intent.yaml")
	comp, plans, profiles, err := compilePlansFromInput("", intentPath, "", filepath.Join("..", "..", "examples", "adapters"), filepath.Join("..", "..", "examples", "profiles"), nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("compile plans: %v", err)
	}
	if len(comp.Intent.Spec.Registries.ByName()) == 0 || comp.Intent.Spec.Registries.Snapshot.Digest == "" {
		t.Fatalf("generated PolicyIntent did not pin registries: %#v", comp.Intent.Spec.Registries)
	}
	ep, prof, err := selectTarget(plans, profiles, "klshield-local")
	if err != nil {
		t.Fatalf("select target: %v", err)
	}
	pack, err := bundler.BuildPolicyPack(ep, prof, bundler.RuntimePolicyConfig{
		Name:           "doc-acceptance-manual-edge",
		IssuedAt:       time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC),
		DefaultTTL:     30 * time.Second,
		Guardrails:     comp.Guardrails,
		DetectionRules: comp.DetectionRules,
		ResponseRules:  comp.ResponseRules,
		AlertRoutes:    comp.AlertRoutes,
	})
	if err != nil {
		t.Fatalf("build policy pack: %v", err)
	}
	if len(pack.Spec.DetectionRules) == 0 || len(pack.Spec.ResponseRules) == 0 || len(pack.Spec.AlertRoutes) == 0 {
		t.Fatalf("runtime response IR missing: detections=%d responses=%d routes=%d", len(pack.Spec.DetectionRules), len(pack.Spec.ResponseRules), len(pack.Spec.AlertRoutes))
	}
	if len(pack.Spec.Guardrails) == 0 {
		t.Fatalf("runtime guardrails missing")
	}
	if len(pack.Spec.GapMetadata) == 0 {
		t.Fatalf("runtime gap metadata missing")
	}
	foundPreviousAction := false
	foundBlastRadius := false
	foundContractMetadata := false
	for _, rule := range pack.Spec.ResponseRules {
		for _, action := range rule.Then {
			if action.Params["previous_action_id"] != nil {
				foundPreviousAction = true
			}
			if action.Params["blast_radius"] != nil {
				foundBlastRadius = true
			}
			if action.Params["audit_required"] == true && action.Params["auto_revert"] != nil {
				foundContractMetadata = true
			}
		}
	}
	if !foundPreviousAction || !foundBlastRadius || !foundContractMetadata {
		t.Fatalf("response safety metadata missing: previous=%v blast=%v contract=%v", foundPreviousAction, foundBlastRadius, foundContractMetadata)
	}
}
