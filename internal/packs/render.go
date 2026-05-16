// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package packs renders Forge policies into deployable LocalPolicyPack YAML
// files that KLIQ can consume via --policy-file.
//
// The LocalPolicyPack format is defined in the kernloom runtime repo at
// pkg/core/policy/pack.go. Types are duplicated here to avoid a cross-repo
// dependency; they will be unified in a shared SDK package in a later phase.
//
// Vocabulary: Forge capability IDs (enforce.traffic.rate_limit) are used
// directly in the output. KLIQ maps them to its internal adapter methods via
// a normalisation table in iq/cmd/kliq/policy_bridge.go. Forge does NOT
// translate to KLIQ-internal IDs — that is KLIQ's responsibility.
package packs

import (
	"fmt"
	"strings"

	"github.com/kernloom/kernloom-forge/internal/validator"
)

// ── KLIQ LocalPolicyPack schema ───────────────────────────────────────────────
// These types mirror kernloom/pkg/core/policy/pack.go exactly.
// When a shared SDK is introduced they will be replaced by the SDK types.

const (
	LocalPolicyPackAPIVersion = "kernloom.io/v1alpha1"
	LocalPolicyPackKind       = "LocalPolicyPack"
)

// LocalPolicyPack is the deployable pack that KLIQ loads via --policy-file.
type LocalPolicyPack struct {
	APIVersion string       `yaml:"apiVersion"`
	Kind       string       `yaml:"kind"`
	Metadata   PackMetadata `yaml:"metadata"`
	Spec       PackSpec     `yaml:"spec"`
}

type PackMetadata struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
}

type PackSpec struct {
	TargetSelector       PackTargetSelector `yaml:"target_selector,omitempty"`
	CapabilitiesRequired []string           `yaml:"capabilities_required,omitempty"`
	Autonomy             PackAutonomy       `yaml:"autonomy"`
	Rules                []PackRule         `yaml:"rules"`
	Exports              PackExports        `yaml:"exports,omitempty"`
}

type PackTargetSelector struct {
	MatchLabels map[string]string `yaml:"match_labels,omitempty"`
}

type PackAutonomy struct {
	DryRun          bool   `yaml:"dry_run"`
	MaxAction       string `yaml:"max_action"`
	AllowLocalBlock bool   `yaml:"allow_local_block"`
}

type PackRule struct {
	Name string   `yaml:"name"`
	When PackWhen `yaml:"when"`
	Then PackThen `yaml:"then"`
}

type PackWhen struct {
	// FsmLevel is a KLIQ-internal enforcement trigger concept.
	// Forge sets it based on the severity of the mapped capability.
	// KLIQ decides WHEN to reach each level via its signal engine.
	FsmLevel string `yaml:"fsm_level,omitempty"`
	Signal   string `yaml:"signal,omitempty"`
}

type PackThen struct {
	Action     string            `yaml:"action"`
	Capability string            `yaml:"capability"` // Forge vocabulary ID
	TTL        string            `yaml:"ttl,omitempty"`
	Params     map[string]string `yaml:"params,omitempty"`
}

type PackExports struct {
	Forge PackExportTarget `yaml:"forge,omitempty"`
}

type PackExportTarget struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint,omitempty"`
}

// ── FSM level table ───────────────────────────────────────────────────────────
// Maps Forge capability IDs to the KLIQ FSM enforcement level and action name.
// Forge capability IDs are passed through unchanged to then.capability —
// KLIQ translates them to adapter calls via its own normalisation table.
// This table only determines the enforcement SEVERITY (which FSM level).

type capLevel struct {
	fsmLevel string // soft | hard | block | observe
	action   string // rate_limit | block | allow | observe
}

var forgeFSMLevel = map[string]capLevel{
	// enforce.access.*
	"enforce.access.deny":         {fsmLevel: "block", action: "block"},
	"enforce.access.allow":        {fsmLevel: "observe", action: "allow"},
	"enforce.access.default_deny": {fsmLevel: "block", action: "block"},

	// enforce.traffic.*
	"enforce.traffic.rate_limit":       {fsmLevel: "soft", action: "rate_limit"},
	"enforce.traffic.connection_limit": {fsmLevel: "soft", action: "rate_limit"},
	"enforce.traffic.bandwidth_limit":  {fsmLevel: "soft", action: "rate_limit"},
	"enforce.traffic.drop":             {fsmLevel: "block", action: "block"},
	"enforce.traffic.quarantine":       {fsmLevel: "block", action: "block"},
	"enforce.traffic.tarpit":           {fsmLevel: "hard", action: "rate_limit"},

	// enforce.network.* (legacy)
	"enforce.network.deny":         {fsmLevel: "block", action: "block"},
	"enforce.network.rate_limit":   {fsmLevel: "soft", action: "rate_limit"},
	"enforce.network.default_deny": {fsmLevel: "block", action: "block"},
	"enforce.network.quarantine":   {fsmLevel: "block", action: "block"},
	"enforce.network.syn_protect":  {fsmLevel: "soft", action: "rate_limit"},
}

// fsmLevelOrder is used to determine the highest enforcement level in a policy.
var fsmLevelOrder = map[string]int{
	"observe": 0, "soft": 1, "hard": 2, "block": 3,
}

// ── RenderRequest / RenderResult ─────────────────────────────────────────────

// RenderRequest is the input to RenderLocalPolicyPack.
type RenderRequest struct {
	Policy   validator.Policy
	DryRun   bool
	ForgeURL string // optional: endpoint for status exports
}

// RenderResult is the output of RenderLocalPolicyPack.
type RenderResult struct {
	Pack     *LocalPolicyPack
	Warnings []string
}

// RenderLocalPolicyPack converts a Forge policy into a KLIQ-compatible
// LocalPolicyPack. Forge capability IDs are used verbatim in then.capability —
// KLIQ maps them to adapter methods via its internal normalisation table.
//
// Only capability_action entries in then: are rendered. CEL conditions in
// when: are not translated — KLIQ's signal engine determines WHEN the FSM
// transitions occur. Forge controls WHAT happens at each level; KLIQ decides
// WHEN.
func RenderLocalPolicyPack(req RenderRequest) (*RenderResult, error) {
	p := req.Policy
	if p.Metadata.ID == "" {
		return nil, fmt.Errorf("policy missing metadata.id")
	}

	result := &RenderResult{}
	var rules []PackRule
	capsRequired := map[string]bool{}
	maxLevel := "observe"

	for i, action := range p.Then {
		if action.Type != "capability_action" {
			continue
		}
		level, ok := forgeFSMLevel[action.Capability]
		if !ok {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("action[%d]: capability %q has no FSM level mapping — skipped", i, action.Capability))
			continue
		}

		rule := PackRule{
			Name: fmt.Sprintf("forge-%s-%s", slugify(p.Metadata.ID), slugify(action.Capability)),
			When: PackWhen{FsmLevel: level.fsmLevel},
			Then: PackThen{
				Action:     level.action,
				Capability: action.Capability, // Forge ID passed through verbatim
				TTL:        extractTTL(action),
			},
		}
		if len(action.Parameters) > 0 {
			rule.Then.Params = stringifyParams(action.Parameters)
		}
		rules = append(rules, rule)
		capsRequired[action.Capability] = true

		if fsmLevelOrder[level.fsmLevel] > fsmLevelOrder[maxLevel] {
			maxLevel = level.fsmLevel
		}
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("policy %s: no renderable capability_action entries — "+
			"ensure then: contains capability_action (not intent_action) entries", p.Metadata.ID)
	}

	labels := map[string]string{"forge.policy_id": p.Metadata.ID}
	if p.Intent != "" {
		labels["forge.intent"] = p.Intent
	}

	pack := &LocalPolicyPack{
		APIVersion: LocalPolicyPackAPIVersion,
		Kind:       LocalPolicyPackKind,
		Metadata: PackMetadata{
			Name:        p.Metadata.ID,
			Description: p.Metadata.Description,
			Labels:      labels,
		},
		Spec: PackSpec{
			CapabilitiesRequired: sortedKeys(capsRequired),
			Autonomy: PackAutonomy{
				DryRun:          req.DryRun,
				MaxAction:       maxActionFrom(maxLevel),
				AllowLocalBlock: maxLevel == "block",
			},
			Rules: rules,
		},
	}

	if req.ForgeURL != "" {
		pack.Spec.Exports = PackExports{
			Forge: PackExportTarget{Enabled: true, Endpoint: req.ForgeURL},
		}
	}

	result.Pack = pack
	return result, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func extractTTL(action validator.PolicyAction) string {
	if action.TTL != "" {
		return action.TTL
	}
	if action.Parameters != nil {
		if ttl, ok := action.Parameters["ttl"].(string); ok {
			return ttl
		}
	}
	return ""
}

func maxActionFrom(fsmLevel string) string {
	switch fsmLevel {
	case "block", "hard":
		return "block"
	case "soft":
		return "rate_limit"
	default:
		return "observe"
	}
}

func stringifyParams(params map[string]any) map[string]string {
	out := make(map[string]string, len(params))
	for k, v := range params {
		out[k] = fmt.Sprintf("%v", v)
	}
	return out
}

func slugify(s string) string {
	return strings.NewReplacer(".", "-", "_", "-", " ", "-").Replace(s)
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys)-1; i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

// SupportedForgeCapabilities returns the Forge capability IDs the renderer
// knows how to map to FSM levels.
func SupportedForgeCapabilities() []string {
	return sortedKeys(func() map[string]bool {
		m := make(map[string]bool, len(forgeFSMLevel))
		for k := range forgeFSMLevel {
			m[k] = true
		}
		return m
	}())
}
