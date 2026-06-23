// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"fmt"
	"strings"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom-forge/internal/api"
	"github.com/kernloom/kernloom-forge/pkg/bundler"
	"github.com/kernloom/kernloom-forge/pkg/core/plan"
	"github.com/kernloom/kernloom-forge/pkg/core/profile"
)

type autoPlacement struct {
	Plan    *plan.EnforcementPlan
	Profile *profile.TargetIntegrationProfile
	Pack    contracts.RuntimePolicyPack
}

func selectAutoPlacement(
	node api.NodeRecord,
	plans []*plan.EnforcementPlan,
	profiles []*profile.TargetIntegrationProfile,
	cfg bundler.RuntimePolicyConfig,
) (*autoPlacement, error) {
	caps := nodeCapabilitySet(node)
	adapters := nodeAdapterSet(node)
	profilesByName := profilesByTargetName(profiles)
	var skipped []string

	for _, candidate := range plans {
		if candidate == nil {
			continue
		}
		target := candidate.Metadata.Target
		prof := profilesByName[target]
		if prof == nil {
			skipped = append(skipped, target+": profile not found")
			continue
		}
		if !candidate.Spec.Summary.Deployable {
			skipped = append(skipped, target+": plan not deployable")
			continue
		}
		if !adapterMatches(adapters, prof.Spec.AdapterRef) {
			skipped = append(skipped, target+": adapter "+prof.Spec.AdapterRef+" not reported")
			continue
		}
		pack, err := bundler.BuildPolicyPack(candidate, prof, cfg)
		if err != nil {
			skipped = append(skipped, target+": "+err.Error())
			continue
		}
		if missing := missingCapabilities(pack.Spec.CapabilitiesRequired, caps); len(missing) > 0 {
			skipped = append(skipped, target+": missing capabilities "+strings.Join(missing, ","))
			continue
		}
		return &autoPlacement{
			Plan:    candidate,
			Profile: prof,
			Pack:    pack,
		}, nil
	}

	reason := strings.Join(skipped, "; ")
	if reason == "" {
		reason = "no compiled targets"
	}
	return nil, fmt.Errorf("%w %q: %s", errNoPolicyAssignment, node.NodeID, reason)
}

func profilesByTargetName(profiles []*profile.TargetIntegrationProfile) map[string]*profile.TargetIntegrationProfile {
	out := make(map[string]*profile.TargetIntegrationProfile, len(profiles))
	for _, prof := range profiles {
		if prof == nil || prof.Metadata.Name == "" {
			continue
		}
		out[prof.Metadata.Name] = prof
	}
	return out
}

func adapterMatches(adapters map[string]bool, adapter string) bool {
	adapter = strings.TrimSpace(adapter)
	if adapter == "" {
		return true
	}
	if adapters[adapter] {
		return true
	}
	if strings.HasPrefix(adapter, "builtin-") {
		return adapters[strings.TrimPrefix(adapter, "builtin-")]
	}
	return adapters["builtin-"+adapter]
}
