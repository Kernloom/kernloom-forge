// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package assessment evaluates config assets against AssessmentPolicy rules.
//
// Flow:
//
//	CI/CD pipeline or operator → forge assess <asset.yaml> --policies <dir>
//	                           → Assess(asset, policies)
//	                           → Result{Verdict, Violations}
//	                           → exit 0 (allow) or exit 1 (deny/warn)
//
// CEL bindings:
//
//	from: asset, path: "spec.containers[0].image"
//	  → resolved via dotpath into the parsed asset YAML/JSON
//	  → available as vars.<name> in the CEL expression
//
// Expressions return true when a violation is found (inverse of runtime CEL,
// where true means "act now"). This mirrors how linters work: the expression
// describes the bad pattern, not the allowed pattern.
package assessment

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"

	"github.com/kernloom/kernloom-forge/internal/validator"
)

// Asset is a config artifact submitted for assessment.
//
// CEL evaluation exposes three top-level variables:
//
//   - document — the full parsed YAML/JSON content (map or list at root)
//   - asset    — metadata about the asset (type, schema_id, format, path, ...)
//   - vars     — named bindings resolved via from:asset path: entries (backward compat)
//
// Example CEL expressions:
//
//	document.kind == "Deployment" && document.spec.template.spec.containers.exists(c, c.image.endsWith(":latest"))
//	asset.asset_type == "kubernetes.manifest" && document.metadata.namespace == "production"
type Asset struct {
	// Meta holds arbitrary key-value metadata exposed as the CEL "asset" variable.
	// Standard keys: asset_type, schema_id, format, path, environment, owner.
	// All are optional; policies may check has(asset.asset_type) before branching.
	Meta map[string]any
	// Data is the parsed document content, exposed as the CEL "document" variable.
	Data map[string]any
}

// ParseAsset parses a YAML or JSON byte slice into an Asset.
// meta is optional key-value metadata exposed as the CEL "asset" variable
// (e.g. map[string]any{"asset_type": "kubernetes.manifest", "environment": "production"}).
func ParseAsset(raw []byte, meta map[string]any) (Asset, error) {
	var data map[string]any
	if err := yaml.Unmarshal(raw, &data); err != nil {
		return Asset{}, fmt.Errorf("parse asset: %w", err)
	}
	if data == nil {
		return Asset{}, fmt.Errorf("parse asset: empty document")
	}
	if meta == nil {
		meta = map[string]any{}
	}
	return Asset{Meta: meta, Data: data}, nil
}

// Violation describes a single policy rule violation found in the asset.
type Violation struct {
	PolicyID    string `yaml:"policy_id"    json:"policy_id"`
	PolicyName  string `yaml:"policy_name"  json:"policy_name,omitempty"`
	Severity    string `yaml:"severity"     json:"severity"` // "error" | "warning" | "info"
	Field       string `yaml:"field"        json:"field,omitempty"`
	Message     string `yaml:"message"      json:"message"`
	Remediation string `yaml:"remediation"  json:"remediation,omitempty"`
}

// Result is the outcome of assessing an asset.
type Result struct {
	// Verdict is "allow", "warn" (warnings only), or "deny" (at least one error).
	Verdict    string      `yaml:"verdict"    json:"verdict"`
	Violations []Violation `yaml:"violations" json:"violations"`
}

// Assess evaluates asset against all AssessmentPolicy (or context:asset Policy)
// entries in policies. Policies of other kinds/contexts are silently skipped.
// Policies are normalized before evaluation so both legacy and canonical formats work.
func Assess(asset Asset, policies []validator.Policy) Result {
	env, err := celEnv()
	if err != nil {
		return Result{Verdict: "deny", Violations: []Violation{{
			PolicyID: "internal", Severity: "error",
			Message: fmt.Sprintf("CEL environment init failed: %v", err),
		}}}
	}

	var violations []Violation
	buf := make(map[string]any, 8) // reused across rules

	for _, policy := range policies {
		// Normalize so spec.rules is always populated.
		policy.Normalize()

		// Accept AssessmentPolicy kind or kind:Policy with context:asset.
		isAssessment := policy.Kind == "AssessmentPolicy" ||
			(policy.Kind == "Policy" && policy.Spec.Context == "asset")
		if !isAssessment {
			continue
		}

		// Evaluate each rule independently. Each rule has its own expression.
		for _, rule := range policy.Spec.Rules {
			if rule.When.Language != "cel" || rule.When.Expression == "" {
				continue
			}
			// Merge shared spec.inputs.bindings into this rule's when.
			mergedBindings := mergeBindings(policy.Spec.Inputs.Bindings, rule.When.Bindings)
			vs := evalRule(env, asset, policy.Metadata.ID, policy.Metadata.Name, rule, mergedBindings, buf)
			violations = append(violations, vs...)
		}
	}

	return Result{Verdict: verdictFrom(violations), Violations: violations}
}

// mergeBindings merges shared and rule-local bindings; rule-local takes precedence.
func mergeBindings(shared, local map[string]validator.PolicyBinding) map[string]validator.PolicyBinding {
	if len(shared) == 0 {
		return local
	}
	merged := make(map[string]validator.PolicyBinding, len(shared)+len(local))
	for k, v := range shared {
		merged[k] = v
	}
	for k, v := range local {
		merged[k] = v
	}
	return merged
}

// evalRule evaluates a single canonical PolicyRule against the asset.
// bindings is the merged set of spec.inputs.bindings + rule.When.Bindings.
func evalRule(env *cel.Env, asset Asset, policyID, policyName string, rule validator.PolicyRule, bindings map[string]validator.PolicyBinding, buf map[string]any) []Violation {
	ast, iss := env.Parse(rule.When.Expression)
	if iss.Err() != nil {
		return []Violation{{
			PolicyID: policyID, Severity: "error",
			Message: fmt.Sprintf("CEL parse error in rule %q: %v", rule.ID, iss.Err()),
		}}
	}
	prog, err := env.Program(ast)
	if err != nil {
		return []Violation{{
			PolicyID: policyID, Severity: "error",
			Message: fmt.Sprintf("CEL program error in rule %q: %v", rule.ID, err),
		}}
	}

	// Resolve asset bindings into the reusable buf.
	for k := range buf {
		delete(buf, k)
	}
	for name, binding := range bindings {
		if binding.From == "asset" {
			val, _ := ResolvePath(asset.Data, binding.Path)
			buf[name] = val
		}
	}

	out, _, err := prog.Eval(map[string]any{
		"vars":     buf,
		"document": asset.Data,
		"asset":    asset.Meta,
	})
	if err != nil {
		// Eval errors (nil dereference on missing field, etc.) → not a violation.
		return nil
	}
	matched, ok := out.Value().(bool)
	if !ok || !matched {
		return nil
	}

	// Expression matched → collect violation effects.
	var violations []Violation
	for _, effect := range rule.Effects {
		if effect.Type != "violation" {
			continue
		}
		sev := effect.Severity
		if sev == "" {
			sev = "error"
		}
		violations = append(violations, Violation{
			PolicyID:    policyID,
			PolicyName:  policyName,
			Severity:    sev,
			Field:       effect.Field,
			Message:     effect.Message,
			Remediation: effect.Remediation,
		})
	}
	return violations
}

func verdictFrom(violations []Violation) string {
	hasError, hasWarn := false, false
	for _, v := range violations {
		switch v.Severity {
		case "error":
			hasError = true
		case "warning":
			hasWarn = true
		}
	}
	if hasError {
		return "deny"
	}
	if hasWarn {
		return "warn"
	}
	return "allow"
}

func celEnv() (*cel.Env, error) {
	return cel.NewEnv(
		// vars: named bindings resolved via from:asset path: entries (backward compat)
		cel.Variable("vars", cel.MapType(cel.StringType, cel.DynType)),
		// document: the full parsed config document — primary access method
		cel.Variable("document", cel.MapType(cel.StringType, cel.DynType)),
		// asset: metadata about the asset (asset_type, schema_id, format, path, ...)
		cel.Variable("asset", cel.MapType(cel.StringType, cel.DynType)),
	)
}

// ResolvePath resolves a dotpath into a nested map[string]any structure.
// Supports dot-separated keys and [N] array indexing.
// Returns (nil, false) when any segment is missing or out of bounds.
//
// Examples:
//
//	ResolvePath(data, "spec.containers[0].image")
//	ResolvePath(data, "metadata.namespace")
//	ResolvePath(data, "spec.containers")   → returns []any
func ResolvePath(data map[string]any, path string) (any, bool) {
	if path == "" {
		return data, true
	}
	var current any = data
	for _, segment := range strings.Split(path, ".") {
		if segment == "" {
			continue
		}
		key, idx, hasIdx := parseSegment(segment)
		switch v := current.(type) {
		case map[string]any:
			child, ok := v[key]
			if !ok {
				return nil, false
			}
			if hasIdx {
				arr, ok := child.([]any)
				if !ok || idx < 0 || idx >= len(arr) {
					return nil, false
				}
				current = arr[idx]
			} else {
				current = child
			}
		case []any:
			if !hasIdx || idx < 0 || idx >= len(v) {
				return nil, false
			}
			current = v[idx]
		default:
			return nil, false
		}
	}
	return current, true
}

// parseSegment splits "containers[2]" into ("containers", 2, true)
// and "spec" into ("spec", 0, false).
func parseSegment(s string) (key string, idx int, hasIdx bool) {
	b := strings.Index(s, "[")
	if b < 0 {
		return s, 0, false
	}
	e := strings.Index(s, "]")
	if e < 0 || e < b {
		return s, 0, false
	}
	n, err := strconv.Atoi(s[b+1 : e])
	if err != nil {
		return s[:b], 0, false
	}
	return s[:b], n, true
}
