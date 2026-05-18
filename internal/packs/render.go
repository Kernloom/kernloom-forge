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
	"time"

	"github.com/kernloom/kernloom-forge/internal/validator"
)

// ── KLIQ LocalPolicyPack schema ───────────────────────────────────────────────
// These types mirror kernloom/pkg/core/policy/pack.go exactly.
// When a shared SDK is introduced they will be replaced by the SDK types.

const (
	// LocalPolicyPackAPIVersion uses the KLIQ-specific API group to signal that
	// this is a compiled runtime artifact, not a Forge canonical policy.
	// Forge source policies use forge.kernloom.io/v1alpha2.
	LocalPolicyPackAPIVersion = "kernloom.io/kliq/v1alpha1"
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
	// IssuedAt is set by Forge at render/sign time. KLIQ uses it for rollback
	// protection: a pack with an earlier IssuedAt than the currently active pack
	// is rejected (CLAUDE.md rule #9).
	IssuedAt string `yaml:"issued_at,omitempty"`
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

// PackWhen is the trigger condition for a pack rule.
// Two forms are supported:
//   - v1.1 (capability-based): Capability is set; KLIQ maps it to an FSM level.
//   - v1.2 (CEL-based): Language=="cel", Expression is a CEL predicate, Bindings
//     declare named variables resolved from live signals and baseline statistics.
//     KLIQ evaluates the expression per-source on every tick.
type PackWhen struct {
	// v1.1 fields
	Capability string `yaml:"capability,omitempty"` // Forge capability ID
	Signal     string `yaml:"signal,omitempty"`

	// v1.2 CEL fields — present when Language == "cel"
	Language   string                 `yaml:"language,omitempty"`
	Bindings   map[string]PackBinding `yaml:"bindings,omitempty"`
	Expression string                 `yaml:"expression,omitempty"`
}

// PackBinding declares a named CEL variable resolved from live signal data or
// baseline statistics. Mirrors validator.PolicyBinding exactly.
type PackBinding struct {
	From      string `yaml:"from"`                // "signal" | "baseline"
	ID        string `yaml:"id,omitempty"`        // signal id  (from: signal)
	Signal    string `yaml:"signal,omitempty"`    // signal id  (from: baseline)
	Scope     string `yaml:"scope,omitempty"`     // "src_ip" | "global" | ...
	Statistic string `yaml:"statistic,omitempty"` // "upper_bound" | "confidence" | "phase" | ...
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
// LocalPolicyPack. Handles both canonical (spec.rules + effects) and legacy
// (then + capability_action) formats by normalizing first.
//
// Forge capability IDs are passed through verbatim — KLIQ maps them to
// adapter methods via its internal normalisation table.
func RenderLocalPolicyPack(req RenderRequest) (*RenderResult, error) {
	p := req.Policy
	if p.Metadata.ID == "" {
		return nil, fmt.Errorf("policy missing metadata.id")
	}
	// Normalize legacy → canonical before rendering.
	p.Normalize()

	result := &RenderResult{}
	var rules []PackRule
	capsRequired := map[string]bool{}
	maxSeverity := 0

	// Iterate canonical spec.rules. Each rule may have multiple effects;
	// only "action" effects are rendered into pack rules.
	for ruleIdx, specRule := range p.Spec.Rules {
		for effectIdx, effect := range specRule.Effects {
			if effect.Type != "action" {
				continue
			}
			capID := effect.Action
			if capID == "" {
				capID = effect.Capability // backward compat
			}
			if capID == "" {
				continue
			}

			sev, ok := capabilitySeverity[capID]
			if !ok {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("rule[%d] effect[%d]: capability %q has no severity mapping — skipped", ruleIdx, effectIdx, capID))
				continue
			}

			// Merge shared spec.inputs.bindings into the rule's when block.
			mergedW := mergedWhen(specRule.When, p.Spec.Inputs.Bindings)
			packWhen := buildPackWhenFromSpec(p, mergedW, capID)

			rule := PackRule{
				Name: fmt.Sprintf("forge-%s-rule%d-%s", slugify(p.Metadata.ID), ruleIdx, slugify(capID)),
				When: packWhen,
				Then: PackThen{
					Capability: capID,
					TTL:        effectTTL(effect),
					Params:     effectParams(effect),
				},
			}
			rules = append(rules, rule)
			capsRequired[capID] = true
			if sev > maxSeverity {
				maxSeverity = sev
			}
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
			IssuedAt:    time.Now().UTC().Format(time.RFC3339),
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

// ── Multi-policy pack ─────────────────────────────────────────────────────────

// MultiRenderRequest is the input to RenderMultiPolicyPack.
type MultiRenderRequest struct {
	// Policies is the ordered list of validated policies to compile into one pack.
	// Rule order in the output matches policy order — policies listed first are
	// evaluated first by KLIQ on each tick.
	Policies []validator.Policy
	// PackName is the name written to metadata.name. Required.
	PackName string
	// ForgeURL is the optional Forge endpoint included in exports.
	ForgeURL string
}

// RenderMultiPolicyPack compiles multiple RuntimePolicy files into a single
// LocalPolicyPack. Each policy contributes its own rules; capabilities_required
// and action_authorization.allowed_capabilities are the union across all policies.
//
// Rule priority: policies are processed in the order they appear in req.Policies.
// Within KLIQ's per-tick evaluation loop the first matching CEL rule wins, so
// order matters — more specific or lower-severity rules should come first.
func RenderMultiPolicyPack(req MultiRenderRequest) (*RenderResult, error) {
	if req.PackName == "" {
		return nil, fmt.Errorf("RenderMultiPolicyPack: PackName is required")
	}
	if len(req.Policies) == 0 {
		return nil, fmt.Errorf("RenderMultiPolicyPack: at least one policy is required")
	}

	result := &RenderResult{}
	var rules []PackRule
	capsRequired := map[string]bool{}
	maxSeverity := 0
	policyIDs := make([]string, 0, len(req.Policies))

	for _, pol := range req.Policies {
		policyIDs = append(policyIDs, pol.Metadata.ID)
		pol.Normalize()

		for ruleIdx, specRule := range pol.Spec.Rules {
			for effectIdx, effect := range specRule.Effects {
				if effect.Type != "action" {
					continue
				}
				capID := effect.Action
				if capID == "" {
					capID = effect.Capability
				}
				if capID == "" {
					continue
				}
				sev, ok := capabilitySeverity[capID]
				if !ok {
					result.Warnings = append(result.Warnings,
						fmt.Sprintf("policy %s rule[%d] effect[%d]: capability %q has no severity mapping — skipped",
							pol.Metadata.ID, ruleIdx, effectIdx, capID))
					continue
				}
				mergedW := mergedWhen(specRule.When, pol.Spec.Inputs.Bindings)
				rule := PackRule{
					Name: fmt.Sprintf("forge-%s-rule%d-%s", slugify(pol.Metadata.ID), ruleIdx, slugify(capID)),
					When: buildPackWhenFromSpec(pol, mergedW, capID),
					Then: PackThen{
						Capability: capID,
						TTL:        effectTTL(effect),
						Params:     effectParams(effect),
					},
				}
				rules = append(rules, rule)
				capsRequired[capID] = true
				if sev > maxSeverity {
					maxSeverity = sev
				}
			}
		}
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("RenderMultiPolicyPack: no renderable capability_action entries across %d policies", len(req.Policies))
	}

	labels := map[string]string{
		"forge.pack_type":    "multi",
		"forge.policy_count": fmt.Sprintf("%d", len(req.Policies)),
		"forge.policies":     strings.Join(policyIDs, ","),
	}

	pack := &LocalPolicyPack{
		APIVersion: LocalPolicyPackAPIVersion,
		Kind:       LocalPolicyPackKind,
		Metadata: PackMetadata{
			Name:        req.PackName,
			Description: fmt.Sprintf("Policies: %s", strings.Join(policyIDs, ", ")),
			Labels:      labels,
			IssuedAt:    time.Now().UTC().Format(time.RFC3339),
		},
		Spec: PackSpec{
			CapabilitiesRequired: sortedKeys(capsRequired),
			ActionAuthorization: PackActionAuthorization{
				AllowedCapabilities: sortedKeys(capsRequired),
				DefaultEffect:       "deny",
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

// mergedWhen merges shared spec.inputs.bindings into a rule's when block.
// Rule-local bindings take precedence on name collision.
func mergedWhen(ruleWhen validator.PolicyWhen, shared map[string]validator.PolicyBinding) validator.PolicyWhen {
	if len(shared) == 0 {
		return ruleWhen
	}
	merged := ruleWhen
	all := make(map[string]validator.PolicyBinding, len(shared)+len(ruleWhen.Bindings))
	for k, v := range shared {
		all[k] = v
	}
	for k, v := range ruleWhen.Bindings {
		all[k] = v // rule-local overrides shared
	}
	merged.Bindings = all
	return merged
}

// buildPackWhenFromSpec builds a PackWhen from a canonical PolicyWhen (spec.rules format).
// CEL expressions and bindings are passed through verbatim for KLIQ evaluation.
// fallbackCapID is used when there is no CEL expression: KLIQ uses when.capability
// to determine which FSM level the rule applies to (v1.1 backward compat).
func buildPackWhenFromSpec(_ validator.Policy, when validator.PolicyWhen, fallbackCapID string) PackWhen {
	if when.Language == "cel" && when.Expression != "" {
		bindings := make(map[string]PackBinding, len(when.Bindings))
		for name, b := range when.Bindings {
			bindings[name] = PackBinding{
				From:      b.From,
				ID:        b.ID,
				Signal:    b.Signal,
				Scope:     b.Scope,
				Statistic: b.Statistic,
			}
		}
		return PackWhen{
			Language:   "cel",
			Bindings:   bindings,
			Expression: when.Expression,
		}
	}
	// No CEL: fall back to v1.1 behavior — KLIQ maps capability → FSM level.
	return PackWhen{Capability: fallbackCapID}
}

// effectTTL extracts the TTL string from a PolicyEffect's constraints map.
func effectTTL(e validator.PolicyEffect) string {
	if e.Constraints == nil {
		return ""
	}
	if ttl, ok := e.Constraints["ttl"].(string); ok {
		return ttl
	}
	return ""
}

// effectParams converts a PolicyEffect's parameters map to map[string]string.
func effectParams(e validator.PolicyEffect) map[string]string {
	if len(e.Parameters) == 0 {
		return nil
	}
	return stringifyParams(e.Parameters)
}

// buildPackWhen builds the PackWhen for a single then-action.
// For CEL policies (language: cel), the full expression and bindings are passed
// through verbatim so KLIQ can evaluate them at runtime. For non-CEL policies
// the Forge capability ID is used directly (v1.1 behaviour).
func buildPackWhen(p validator.Policy, action validator.PolicyAction) PackWhen {
	if p.When.Language == "cel" && p.When.Expression != "" {
		bindings := make(map[string]PackBinding, len(p.When.Bindings))
		for name, b := range p.When.Bindings {
			bindings[name] = PackBinding{
				From:      b.From,
				ID:        b.ID,
				Signal:    b.Signal,
				Scope:     b.Scope,
				Statistic: b.Statistic,
			}
		}
		return PackWhen{
			Language:   "cel",
			Bindings:   bindings,
			Expression: p.When.Expression,
		}
	}
	return PackWhen{Capability: action.Capability}
}

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
