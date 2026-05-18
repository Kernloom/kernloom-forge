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
	TargetSelector       PackTargetSelector      `yaml:"target_selector,omitempty"`
	CapabilitiesRequired []string                `yaml:"capabilities_required,omitempty"`
	ActionAuthorization  PackActionAuthorization `yaml:"action_authorization,omitempty"`
	Rules                []PackRule              `yaml:"rules"`
	Exports              PackExports             `yaml:"exports,omitempty"`
}

type PackTargetSelector struct {
	MatchLabels map[string]string `yaml:"match_labels,omitempty"`
}

// PackActionAuthorization is the v1.1 enforcement ceiling section.
// It replaces the v1.0 autonomy section: capability IDs are used throughout,
// no KLIQ-internal shorthands (max_action, allow_local_block) are emitted.
// KLIQ derives the enforcement ceiling from AllowedCapabilities directly.
type PackActionAuthorization struct {
	// AllowedCapabilities is the explicit set of Forge capability IDs this
	// policy authorises. KLIQ caps enforcement to the highest-severity entry.
	AllowedCapabilities []string `yaml:"allowed_capabilities,omitempty"`
	// DefaultEffect is "deny" — capabilities not in the list are refused.
	DefaultEffect string `yaml:"default_effect,omitempty"`
}

type PackRule struct {
	Name string   `yaml:"name"`
	When PackWhen `yaml:"when"`
	Then PackThen `yaml:"then"`
}

// PackWhen is the v1.1 trigger: a Forge capability ID.
// KLIQ maps the capability to its internal FSM level; Forge has no knowledge
// of KLIQ-internal level names (soft/hard/block).
type PackWhen struct {
	Capability string `yaml:"capability,omitempty"` // Forge capability ID
	Signal     string `yaml:"signal,omitempty"`
}

// PackThen carries the enforcement effect in pure Forge vocabulary.
// The v1.0 action shorthand is gone; the capability ID is the full descriptor.
type PackThen struct {
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

// ── Capability severity table ─────────────────────────────────────────────────
// Maps Forge capability IDs to an enforcement severity used INTERNALLY by the
// renderer to determine the AllowedCapabilities list and DefaultEffect.
// Nothing from this table is written to the pack output — Forge vocabulary IDs
// are passed through verbatim; KLIQ owns the FSM-level mapping.

// capabilitySeverity maps Forge capability IDs to severity (0=observe … 3=block).
var capabilitySeverity = map[string]int{
	// observe / allow
	"enforce.access.allow": 0,

	// soft rate-limit
	"enforce.traffic.rate_limit":       1,
	"enforce.traffic.connection_limit": 1,
	"enforce.traffic.bandwidth_limit":  1,
	"enforce.network.rate_limit":       1,
	"enforce.network.syn_protect":      1,

	// hard rate-limit / tarpit
	"enforce.traffic.tarpit": 2,

	// block / drop
	"enforce.access.deny":          3,
	"enforce.access.default_deny":  3,
	"enforce.traffic.drop":         3,
	"enforce.traffic.quarantine":   3,
	"enforce.network.deny":         3,
	"enforce.network.default_deny": 3,
	"enforce.network.quarantine":   3,
}

// ── RenderRequest / RenderResult ─────────────────────────────────────────────

// RenderRequest is the input to RenderLocalPolicyPack.
type RenderRequest struct {
	Policy   validator.Policy
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
	maxSeverity := 0

	for i, action := range p.Then {
		if action.Type != "capability_action" {
			continue
		}
		sev, ok := capabilitySeverity[action.Capability]
		if !ok {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("action[%d]: capability %q has no severity mapping — skipped", i, action.Capability))
			continue
		}

		rule := PackRule{
			Name: fmt.Sprintf("forge-%s-%s", slugify(p.Metadata.ID), slugify(action.Capability)),
			// when.capability uses the Forge ID directly — no KLIQ-internal level names.
			When: PackWhen{Capability: action.Capability},
			Then: PackThen{
				Capability: action.Capability, // Forge ID passed through verbatim
				TTL:        extractTTL(action),
			},
		}
		if len(action.Parameters) > 0 {
			rule.Then.Params = stringifyParams(action.Parameters)
		}
		rules = append(rules, rule)
		capsRequired[action.Capability] = true

		if sev > maxSeverity {
			maxSeverity = sev
		}
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("policy %s: no renderable capability_action entries — "+
			"ensure then: contains capability_action (not intent_action) entries", p.Metadata.ID)
	}

	// Detect enforcement mode: directive when any rule carries an explicit rate_pps.
	enforcementMode := "autonomy"
	for _, rule := range rules {
		if _, ok := rule.Then.Params["rate_pps"]; ok {
			enforcementMode = "directive"
			break
		}
	}

	labels := map[string]string{
		"forge.policy_id":        p.Metadata.ID,
		"forge.enforcement_mode": enforcementMode,
	}
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
			// AllowedCapabilities = every capability the policy exercises.
			// KLIQ derives the enforcement ceiling from this list — no max_action shorthand.
			ActionAuthorization: PackActionAuthorization{
				AllowedCapabilities: sortedKeys(capsRequired),
				DefaultEffect:       "deny",
			},
			Rules: rules,
		},
	}
	_ = maxSeverity // available for future use (e.g. threat-level annotation)

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
// knows how to handle (i.e. has a severity mapping for).
func SupportedForgeCapabilities() []string {
	return sortedKeys(func() map[string]bool {
		m := make(map[string]bool, len(capabilitySeverity))
		for k := range capabilitySeverity {
			m[k] = true
		}
		return m
	}())
}
