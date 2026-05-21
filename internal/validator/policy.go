// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package validator

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kernloom/kernloom-forge/internal/registry"
)

// ── Binding ───────────────────────────────────────────────────────────────────

// PolicyBinding resolves a named CEL variable from live signal, baseline data,
// or a parsed config asset field.
//
//   - from: "signal"   requires id + scope
//   - from: "baseline" requires signal + scope + statistic
//   - from: "asset"    requires path (dotpath into the submitted document)
type PolicyBinding struct {
	From      string `yaml:"from"`
	ID        string `yaml:"id,omitempty"`     // signal id  (from: signal)
	Signal    string `yaml:"signal,omitempty"` // signal id  (from: baseline)
	Scope     string `yaml:"scope,omitempty"`
	Statistic string `yaml:"statistic,omitempty"` // (from: baseline)
	Path      string `yaml:"path,omitempty"`      // dotpath    (from: asset)
}

// ── When ─────────────────────────────────────────────────────────────────────

// PolicyWhen is the condition block of a single rule.
// Bindings here are merged with spec.inputs.bindings at evaluation time;
// per-rule bindings take precedence on name collision.
type PolicyWhen struct {
	Language   string                   `yaml:"language"`
	Expression string                   `yaml:"expression"`
	Bindings   map[string]PolicyBinding `yaml:"bindings,omitempty"` // rule-local overrides
	// Legacy simple matchers (non-CEL) — preserved for backward compat.
	All []map[string]any `yaml:"all,omitempty"`
	Any []map[string]any `yaml:"any,omitempty"`
}

// ── Effect ────────────────────────────────────────────────────────────────────

// PolicyEffect is a single effect produced when a rule matches.
// The Type field determines which other fields are meaningful.
//
// type: action      — execute a Forge capability (Action or Capability field, Target, Constraints)
// type: violation   — asset assessment violation (Severity, Field, Message, Remediation)
// type: finding     — compliance finding (Severity, Category, Message)
// type: decision    — policy-level decision (Decision, DisableActions, AllowActions)
// type: recommendation — suggest without enforcing (Action, Reason)
// type: notify      — alert or notification (Channel, Severity, Message)
// type: export      — export event/metric (Sink, EventType)
type PolicyEffect struct {
	Type string `yaml:"type"`

	// action fields
	Action      string         `yaml:"action,omitempty"`     // canonical Forge capability ID
	Capability  string         `yaml:"capability,omitempty"` // backward compat alias for action
	Intent      string         `yaml:"intent,omitempty"`     // intent_action backward compat
	Target      map[string]any `yaml:"target,omitempty"`
	Parameters  map[string]any `yaml:"parameters,omitempty"`
	Constraints map[string]any `yaml:"constraints,omitempty"` // ttl, max_duration, max_drop_ratio

	// violation / finding fields
	Severity    string `yaml:"severity,omitempty"` // "error" | "warning" | "info"
	Field       string `yaml:"field,omitempty"`
	Message     string `yaml:"message,omitempty"`
	Remediation string `yaml:"remediation,omitempty"`
	Category    string `yaml:"category,omitempty"`

	// decision fields
	Decision       string   `yaml:"decision,omitempty"`
	DisableActions []string `yaml:"disable_actions,omitempty"`
	AllowActions   []string `yaml:"allow_actions,omitempty"`

	// notify / export fields
	Channel   string `yaml:"channel,omitempty"`
	Sink      string `yaml:"sink,omitempty"`
	EventType string `yaml:"event_type,omitempty"`

	// shared
	Reason string `yaml:"reason,omitempty"`
}

// ── Rule ─────────────────────────────────────────────────────────────────────

// PolicyRule is one condition + its effects within a policy.
// Each rule has its own CEL expression evaluated independently.
// This enables true per-rule escalation: different rules have different thresholds.
type PolicyRule struct {
	ID      string         `yaml:"id"`
	When    PolicyWhen     `yaml:"when"`
	Effects []PolicyEffect `yaml:"effects"`
}

// ── Spec ─────────────────────────────────────────────────────────────────────

// PolicyRequirements declares the technical prerequisites a policy needs.
type PolicyRequirements struct {
	// Capabilities is the canonical form (spec.requirements.capabilities).
	// RequiredCapabilities is kept for backward compat with the top-level requirements block.
	Capabilities         []string `yaml:"capabilities,omitempty"`
	RequiredCapabilities []string `yaml:"required_capabilities,omitempty"` // backward compat
	MinGranularity       []string `yaml:"min_granularity,omitempty"`
	SemanticDepth        string   `yaml:"semantic_depth,omitempty"`
	Degradation          struct {
		Allow                   bool     `yaml:"allow"`
		AcceptableGranularities []string `yaml:"acceptable_granularities"`
		RequireApproval         bool     `yaml:"require_approval"`
	} `yaml:"degradation,omitempty"`
}

// effectiveCapabilities returns the merged list of required capabilities,
// preferring spec.requirements.capabilities over the legacy required_capabilities.
func (r *PolicyRequirements) effectiveCapabilities() []string {
	if len(r.Capabilities) > 0 {
		return r.Capabilities
	}
	return r.RequiredCapabilities
}

// PolicyInputs holds bindings shared across all rules in the policy.
type PolicyInputs struct {
	Bindings map[string]PolicyBinding `yaml:"bindings,omitempty"`
}

// PolicySpec is the canonical policy specification (spec: block).
type PolicySpec struct {
	Context      string             `yaml:"context,omitempty"` // runtime|asset|inventory|trust|event
	Intent       string             `yaml:"intent,omitempty"`
	Target       map[string]any     `yaml:"target,omitempty"`
	Requirements PolicyRequirements `yaml:"requirements,omitempty"`
	Inputs       PolicyInputs       `yaml:"inputs,omitempty"`
	Rules        []PolicyRule       `yaml:"rules,omitempty"`
	Bounds       map[string]any     `yaml:"bounds,omitempty"`
}

// BaselineRequirements declares which baseline signal a policy depends on.
type BaselineRequirements struct {
	Signal          string   `yaml:"signal"`
	PreferredScopes []string `yaml:"preferred_scopes"`
	MinConfidence   float64  `yaml:"min_confidence"`
	FallbackAllowed bool     `yaml:"fallback_allowed"`
}

// ── Policy (top-level) ────────────────────────────────────────────────────────

// Policy is the parsed form of any policy document.
//
// Canonical form uses kind: Policy with spec.context.
// Legacy forms (RuntimePolicy, AssessmentPolicy, etc.) are normalized to the
// canonical form by Normalize() before validation.
type Policy struct {
	Kind       string `yaml:"kind"`
	APIVersion string `yaml:"apiVersion"`
	Metadata   struct {
		ID          string `yaml:"id"`
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	} `yaml:"metadata"`

	// Canonical spec block (kind: Policy).
	Spec PolicySpec `yaml:"spec,omitempty"`

	// ── Legacy top-level fields (kind: RuntimePolicy / AssessmentPolicy) ──────
	// Preserved for backward compat. Normalize() migrates them into Spec.

	Intent               string               `yaml:"intent,omitempty"`
	Target               map[string]any       `yaml:"target,omitempty"`
	Requirements         PolicyRequirements   `yaml:"requirements,omitempty"`
	BaselineRequirements BaselineRequirements `yaml:"baseline_requirements,omitempty"`
	When                 PolicyWhen           `yaml:"when,omitempty"`
	Then                 []PolicyAction       `yaml:"then,omitempty"`
}

// PolicyAction is the legacy then: action type (pre-canonical model).
// Normalize() converts these to PolicyEffect entries in Spec.Rules.
type PolicyAction struct {
	Type       string         `yaml:"type"`
	Capability string         `yaml:"capability,omitempty"`
	Intent     string         `yaml:"intent,omitempty"`
	Target     map[string]any `yaml:"target,omitempty"`
	Parameters map[string]any `yaml:"parameters,omitempty"`
	TTL        string         `yaml:"ttl,omitempty"`
	Reason     string         `yaml:"reason,omitempty"`
	// Violation-specific fields (for type: violation in legacy format)
	Severity    string `yaml:"severity,omitempty"`
	Field       string `yaml:"field,omitempty"`
	Message     string `yaml:"message,omitempty"`
	Remediation string `yaml:"remediation,omitempty"`
}

// ── Normalization ─────────────────────────────────────────────────────────────

// Normalize converts legacy policy formats (RuntimePolicy, AssessmentPolicy, etc.)
// into the canonical Policy format with spec.context, spec.inputs.bindings,
// and spec.rules[].effects[].
//
// After normalization all validation operates on Spec only.
func (p *Policy) Normalize() {
	// 1. Infer spec.context from Kind.
	if p.Spec.Context == "" {
		switch p.Kind {
		case "RuntimePolicy":
			p.Spec.Context = "runtime"
		case "AssessmentPolicy":
			p.Spec.Context = "asset"
		case "InventoryPolicy":
			p.Spec.Context = "inventory"
		case "TrustPolicy":
			p.Spec.Context = "trust"
		case "EventPolicy":
			p.Spec.Context = "event"
		}
	}

	// 2. Pull top-level legacy fields into Spec.
	if p.Spec.Intent == "" && p.Intent != "" {
		p.Spec.Intent = p.Intent
	}
	if len(p.Spec.Requirements.effectiveCapabilities()) == 0 {
		p.Spec.Requirements = p.Requirements
	}

	// 3. Move when.bindings → spec.inputs.bindings.
	if len(p.When.Bindings) > 0 && len(p.Spec.Inputs.Bindings) == 0 {
		p.Spec.Inputs.Bindings = p.When.Bindings
	}

	// 4. Convert legacy when + then → spec.rules.
	// Triggers when the old format provides either a when expression, a then list, or both.
	if len(p.Spec.Rules) == 0 && (p.When.Expression != "" || p.When.Language != "" || len(p.Then) > 0) {
		when := p.When
		when.Bindings = nil // bindings are now in Spec.Inputs
		rule := PolicyRule{
			ID:   "rule-0",
			When: when,
		}
		for _, action := range p.Then {
			rule.Effects = append(rule.Effects, legacyActionToEffect(action))
		}
		p.Spec.Rules = []PolicyRule{rule}
	}
}

// legacyActionToEffect converts a legacy PolicyAction (then: block) to a PolicyEffect.
func legacyActionToEffect(a PolicyAction) PolicyEffect {
	e := PolicyEffect{
		Target:      a.Target,
		Parameters:  a.Parameters,
		Reason:      a.Reason,
		Severity:    a.Severity,
		Field:       a.Field,
		Message:     a.Message,
		Remediation: a.Remediation,
	}
	switch a.Type {
	case "capability_action":
		e.Type = "action"
		e.Action = a.Capability
	case "intent_action":
		e.Type = "action"
		e.Intent = a.Intent
	case "violation":
		e.Type = "violation"
	case "event_action", "export_action":
		e.Type = "export"
	case "audit_action":
		e.Type = "notify"
	default:
		e.Type = a.Type
	}
	if a.TTL != "" {
		if e.Constraints == nil {
			e.Constraints = map[string]any{}
		}
		e.Constraints["ttl"] = a.TTL
	}
	return e
}

// bindingNameRe matches valid CEL identifiers.
var bindingNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// ── Parse + Validate ──────────────────────────────────────────────────────────

// ParsePolicyFile parses a policy file without validating it.
func ParsePolicyFile(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read %s: %w", path, err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return p, nil
}

// ValidatePolicyFile loads, normalizes and validates a single policy file.
func ValidatePolicyFile(path string, reg *registry.Registry) error {
	p, err := ParsePolicyFile(path)
	if err != nil {
		return err
	}
	return ValidatePolicy(&p, reg)
}

// ValidatePolicy normalizes and validates a parsed Policy against the registry.
func ValidatePolicy(p *Policy, reg *registry.Registry) error {
	if p.Metadata.ID == "" {
		return fmt.Errorf("policy missing metadata.id")
	}

	// Normalize before validation so all checks operate on canonical Spec.
	p.Normalize()

	// Validate kind.
	validKinds := map[string]bool{
		"Policy":           true,
		"RuntimePolicy":    true,
		"AssessmentPolicy": true,
		"InventoryPolicy":  true,
		"TrustPolicy":      true,
		"EventPolicy":      true,
	}
	if !validKinds[p.Kind] {
		return fmt.Errorf("policy %s: unknown kind %q", p.Metadata.ID, p.Kind)
	}

	// Validate context.
	if p.Spec.Context != "" && len(reg.PolicyContexts) > 0 {
		if !reg.HasPolicyContext(p.Spec.Context) {
			return fmt.Errorf("policy %s: unknown context %q", p.Metadata.ID, p.Spec.Context)
		}
	}

	// Validate top-level intent reference.
	intent := p.Spec.Intent
	if intent == "" {
		intent = p.Intent
	}
	if intent != "" {
		if strings.HasPrefix(intent, "x.") {
			return fmt.Errorf("policy %s: extension intent %q not allowed in strict mode", p.Metadata.ID, intent)
		}
		if !reg.HasIntent(intent) {
			return fmt.Errorf("policy %s: unknown intent %q", p.Metadata.ID, intent)
		}
	}

	// Validate requirements block.
	if err := validatePolicyRequirements(p, reg); err != nil {
		return err
	}

	// Validate baseline_requirements block (legacy field, still supported).
	if err := validateBaselineRequirements(p, reg); err != nil {
		return err
	}

	// Validate shared input bindings.
	for name, binding := range p.Spec.Inputs.Bindings {
		if !bindingNameRe.MatchString(name) {
			return fmt.Errorf("policy %s: binding name %q is not a valid identifier", p.Metadata.ID, name)
		}
		if err := validateBinding(p.Metadata.ID, name, &binding, reg); err != nil {
			return err
		}
	}

	// Validate rules.
	if len(p.Spec.Rules) == 0 {
		return fmt.Errorf("policy %s: spec.rules must contain at least one rule", p.Metadata.ID)
	}
	for i, rule := range p.Spec.Rules {
		if err := validateRule(p, i, &rule, reg); err != nil {
			return err
		}
	}

	return nil
}

func validatePolicyRequirements(p *Policy, reg *registry.Registry) error {
	caps := p.Spec.Requirements.effectiveCapabilities()
	for _, capID := range caps {
		if strings.HasPrefix(capID, "x.") {
			return fmt.Errorf("policy %s: extension capability %q in requirements not allowed", p.Metadata.ID, capID)
		}
		if !reg.HasCapability(capID) {
			return fmt.Errorf("policy %s: requirements references unknown capability %q", p.Metadata.ID, capID)
		}
	}
	for _, g := range p.Spec.Requirements.MinGranularity {
		if !reg.HasGranularity(g) {
			return fmt.Errorf("policy %s: requirements.min_granularity references unknown granularity %q", p.Metadata.ID, g)
		}
	}
	for _, g := range p.Spec.Requirements.Degradation.AcceptableGranularities {
		if !reg.HasGranularity(g) {
			return fmt.Errorf("policy %s: degradation.acceptable_granularities references unknown granularity %q", p.Metadata.ID, g)
		}
	}

	// Also validate legacy top-level requirements block if spec.requirements is empty.
	if len(caps) == 0 {
		for _, capID := range p.Requirements.RequiredCapabilities {
			if strings.HasPrefix(capID, "x.") {
				continue
			}
			if !reg.HasCapability(capID) {
				return fmt.Errorf("policy %s: requirements references unknown capability %q", p.Metadata.ID, capID)
			}
		}
	}
	return nil
}

func validateBaselineRequirements(p *Policy, reg *registry.Registry) error {
	if p.BaselineRequirements.Signal == "" {
		return nil
	}
	if !reg.HasSignal(p.BaselineRequirements.Signal) {
		return fmt.Errorf("policy %s: baseline_requirements.signal references unknown signal %q",
			p.Metadata.ID, p.BaselineRequirements.Signal)
	}
	for _, sc := range p.BaselineRequirements.PreferredScopes {
		if !reg.HasScope(sc) && !reg.HasGranularity(sc) {
			return fmt.Errorf("policy %s: baseline_requirements.preferred_scopes references unknown scope %q",
				p.Metadata.ID, sc)
		}
	}
	return nil
}

func validateRule(p *Policy, idx int, rule *PolicyRule, reg *registry.Registry) error {
	// Validate rule-local bindings.
	for name, binding := range rule.When.Bindings {
		if !bindingNameRe.MatchString(name) {
			return fmt.Errorf("policy %s rule[%d]: binding name %q is not a valid identifier", p.Metadata.ID, idx, name)
		}
		if err := validateBinding(p.Metadata.ID, name, &binding, reg); err != nil {
			return fmt.Errorf("policy %s rule[%d]: %w", p.Metadata.ID, idx, err)
		}
	}

	// Validate effects.
	if len(rule.Effects) == 0 {
		return fmt.Errorf("policy %s rule[%d]: effects must contain at least one entry", p.Metadata.ID, idx)
	}
	for j, effect := range rule.Effects {
		if err := validateEffect(p, idx, j, &effect, reg); err != nil {
			return err
		}
	}
	return nil
}

func validateEffect(p *Policy, ruleIdx, effectIdx int, e *PolicyEffect, reg *registry.Registry) error {
	// Validate effect type exists.
	if e.Type == "" {
		return fmt.Errorf("policy %s rule[%d] effect[%d]: missing type", p.Metadata.ID, ruleIdx, effectIdx)
	}
	if len(reg.EffectTypes) > 0 && !reg.HasEffectType(e.Type) {
		return fmt.Errorf("policy %s rule[%d] effect[%d]: unknown effect type %q", p.Metadata.ID, ruleIdx, effectIdx, e.Type)
	}

	// Validate effect is allowed for context.
	if p.Spec.Context != "" && len(reg.PolicyContexts) > 0 {
		if !reg.EffectAllowedForContext(p.Spec.Context, e.Type) {
			return fmt.Errorf("policy %s rule[%d] effect[%d]: effect type %q is not allowed in context %q",
				p.Metadata.ID, ruleIdx, effectIdx, e.Type, p.Spec.Context)
		}
	}

	switch e.Type {
	case "action":
		capID := e.Action
		if capID == "" {
			capID = e.Capability // backward compat
		}
		if capID == "" && e.Intent == "" {
			return fmt.Errorf("policy %s rule[%d] effect[%d]: action effect requires action or intent field",
				p.Metadata.ID, ruleIdx, effectIdx)
		}
		// Validate constraint keys against the action_constraints registry.
		if len(reg.ActionConstraints) > 0 {
			for key := range e.Constraints {
				if !reg.HasActionConstraint(key) {
					return fmt.Errorf("policy %s rule[%d] effect[%d]: unknown constraint %q — not in action_constraints registry",
						p.Metadata.ID, ruleIdx, effectIdx, key)
				}
				if !reg.ConstraintValidForEffect(key, e.Type) {
					return fmt.Errorf("policy %s rule[%d] effect[%d]: constraint %q is not valid for effect type %q",
						p.Metadata.ID, ruleIdx, effectIdx, key, e.Type)
				}
			}
		}
		if capID != "" {
			if strings.HasPrefix(capID, "x.") {
				return fmt.Errorf("policy %s rule[%d] effect[%d]: extension capability %q not allowed in strict mode",
					p.Metadata.ID, ruleIdx, effectIdx, capID)
			}
			if !reg.HasCapability(capID) {
				return fmt.Errorf("policy %s rule[%d] effect[%d]: unknown capability %q",
					p.Metadata.ID, ruleIdx, effectIdx, capID)
			}
			// Validate parameters against the capability's declared allowed_parameters.
			cap := reg.Capabilities[capID]
			for k, v := range e.Parameters {
				spec, ok := cap.AllowedParameters[k]
				if !ok {
					return fmt.Errorf("policy %s rule[%d] effect[%d]: parameter %q not allowed for capability %q",
						p.Metadata.ID, ruleIdx, effectIdx, k, capID)
				}
				if err := validateParamValue(k, v, spec.Type); err != nil {
					return fmt.Errorf("policy %s rule[%d] effect[%d]: parameter %q: %w",
						p.Metadata.ID, ruleIdx, effectIdx, k, err)
				}
			}
		}
		if e.Intent != "" {
			if strings.HasPrefix(e.Intent, "x.") {
				return fmt.Errorf("policy %s rule[%d] effect[%d]: extension intent %q not allowed in strict mode",
					p.Metadata.ID, ruleIdx, effectIdx, e.Intent)
			}
			if !reg.HasIntent(e.Intent) {
				return fmt.Errorf("policy %s rule[%d] effect[%d]: unknown intent %q",
					p.Metadata.ID, ruleIdx, effectIdx, e.Intent)
			}
		}

	case "violation":
		if e.Message == "" {
			return fmt.Errorf("policy %s rule[%d] effect[%d]: violation effect requires message",
				p.Metadata.ID, ruleIdx, effectIdx)
		}
		validSev := map[string]bool{"error": true, "warning": true, "info": true, "": true}
		if !validSev[e.Severity] {
			return fmt.Errorf("policy %s rule[%d] effect[%d]: violation severity %q must be error, warning, or info",
				p.Metadata.ID, ruleIdx, effectIdx, e.Severity)
		}

	case "notify", "export":
		// Validate constraint keys for notify/export effects too.
		if len(reg.ActionConstraints) > 0 {
			for key := range e.Constraints {
				if !reg.HasActionConstraint(key) {
					return fmt.Errorf("policy %s rule[%d] effect[%d]: unknown constraint %q",
						p.Metadata.ID, ruleIdx, effectIdx, key)
				}
				if !reg.ConstraintValidForEffect(key, e.Type) {
					return fmt.Errorf("policy %s rule[%d] effect[%d]: constraint %q is not valid for effect type %q",
						p.Metadata.ID, ruleIdx, effectIdx, key, e.Type)
				}
			}
		}

	case "finding", "recommendation", "decision":
		// Valid — detailed validation in later phases.

	default:
		// Unknown effect type already caught above; this is unreachable.
	}
	return nil
}

func validateBinding(policyID, name string, b *PolicyBinding, reg *registry.Registry) error {
	switch b.From {
	case "signal":
		if b.ID == "" {
			return fmt.Errorf("policy %s binding %q: from:signal requires id", policyID, name)
		}
		if !reg.HasSignal(b.ID) {
			return fmt.Errorf("policy %s binding %q: references unknown signal %q", policyID, name, b.ID)
		}
		if b.Scope != "" && !reg.HasScope(b.Scope) && !reg.HasGranularity(b.Scope) {
			return fmt.Errorf("policy %s binding %q: references unknown scope %q", policyID, name, b.Scope)
		}

	case "baseline":
		if b.Signal == "" {
			return fmt.Errorf("policy %s binding %q: from:baseline requires signal", policyID, name)
		}
		if !reg.HasSignal(b.Signal) {
			return fmt.Errorf("policy %s binding %q: references unknown signal %q", policyID, name, b.Signal)
		}
		if b.Scope == "" {
			return fmt.Errorf("policy %s binding %q: from:baseline requires scope", policyID, name)
		}
		if !reg.HasScope(b.Scope) && !reg.HasGranularity(b.Scope) {
			return fmt.Errorf("policy %s binding %q: references unknown scope %q", policyID, name, b.Scope)
		}
		if b.Statistic == "" {
			return fmt.Errorf("policy %s binding %q: from:baseline requires statistic", policyID, name)
		}
		if !reg.HasBaselineStatistic(b.Statistic) {
			return fmt.Errorf("policy %s binding %q: references unknown baseline_statistic %q", policyID, name, b.Statistic)
		}

	case "asset":
		if b.Path == "" {
			return fmt.Errorf("policy %s binding %q: from:asset requires path", policyID, name)
		}

	case "":
		return fmt.Errorf("policy %s binding %q: missing from (signal, baseline, or asset)", policyID, name)

	default:
		return fmt.Errorf("policy %s binding %q: unknown from value %q (must be signal, baseline, or asset)", policyID, name, b.From)
	}
	return nil
}

func validateParamValue(key string, val any, typ string) error {
	switch typ {
	case "uint":
		switch v := val.(type) {
		case int:
			if v < 0 {
				return fmt.Errorf("must be >= 0, got %d", v)
			}
		case float64:
			if v < 0 || float64(int64(v)) != v {
				return fmt.Errorf("must be a non-negative integer, got %g", v)
			}
		default:
			return fmt.Errorf("must be a uint (integer), got %T", val)
		}
	case "string":
		if _, ok := val.(string); !ok {
			return fmt.Errorf("must be a string, got %T", val)
		}
	case "float":
		switch val.(type) {
		case int, float64:
		default:
			return fmt.Errorf("must be a number, got %T", val)
		}
	case "bool":
		if _, ok := val.(bool); !ok {
			return fmt.Errorf("must be a bool, got %T", val)
		}
	}
	return nil
}

// ── Policy → YAML (for normalize output) ─────────────────────────────────────

// MarshalNormalized returns the canonical Policy as YAML after normalization.
func MarshalNormalized(p *Policy) ([]byte, error) {
	p.Normalize()
	// Emit as kind: Policy with spec block.
	canonical := struct {
		Kind       string `yaml:"kind"`
		APIVersion string `yaml:"apiVersion"`
		Metadata   any    `yaml:"metadata"`
		Spec       any    `yaml:"spec"`
	}{
		Kind:       "Policy",
		APIVersion: p.APIVersion,
		Metadata:   p.Metadata,
		Spec:       p.Spec,
	}
	return yaml.Marshal(canonical)
}
