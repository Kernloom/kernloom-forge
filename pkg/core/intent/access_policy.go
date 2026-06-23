// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package intent

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	contracts "github.com/kernloom/kernloom-contracts"
	registries "github.com/kernloom/kernloom-registries"
	"gopkg.in/yaml.v3"
)

// AccessPolicy expresses who may access what resource under which conditions.
// It is the primary enterprise policy kind for Zero Trust access decisions.
//
// An AccessPolicy must be vendor-neutral: it must not reference Zscaler,
// OpenZiti, netfilter, or any other target-specific construct. Adapters
// translate it into target-specific representations via RequirementMappings.
//
// Example YAML:
//
//	apiVersion: kernloom.io/v1
//	kind: AccessPolicy
//	metadata:
//	  name: investor-apps-access
//	  owner: security-architecture
//	spec:
//	  subject:
//	    type: role
//	    ref: investors
//	  action: access
//	  resource:
//	    type: application_group
//	    ref: investor-apps
//	  conditions:
//	    - id: require-mfa
//	      type: authentication_strength
//	      signal: session.authentication.strength
//	      operator: eq
//	      value: mfa
//	  effect: allow
type AccessPolicy struct {
	APIVersion string           `yaml:"apiVersion"`
	Kind       PolicyKind       `yaml:"kind"`
	Metadata   PolicyMetadata   `yaml:"metadata"`
	Spec       AccessPolicySpec `yaml:"spec"`
}

// AccessPolicySpec is the normative body of an AccessPolicy.
// It is distinct from the specs of other policy kinds (NetworkPolicySpec,
// AdmissionPolicySpec, etc.) which have different principal models.
type AccessPolicySpec struct {
	Subject                Subject                 `yaml:"subject"`
	Action                 string                  `yaml:"action"`
	Resource               Resource                `yaml:"resource"`
	Requirements           []string                `yaml:"requirements,omitempty"`
	Conditions             []Condition             `yaml:"conditions,omitempty"`
	Effect                 string                  `yaml:"effect"` // allow | deny
	EnforcementConstraints *EnforcementConstraints `yaml:"enforcementConstraints,omitempty"`
}

// Subject identifies who the policy applies to.
// type: role | group | user | service_account | any
type Subject struct {
	Type string `yaml:"type"`
	Ref  string `yaml:"ref,omitempty"`
}

// Resource identifies what the policy protects.
// type: application | application_group | api | service | endpoint | database |
// storage | secret | network_segment | infrastructure_asset | any
type Resource struct {
	Type string `yaml:"type"`
	Ref  string `yaml:"ref,omitempty"`
}

// Condition is a single atomic requirement that must hold for the effect to
// apply. It supports two equivalent formats that can be mixed freely:
//
// Structured format — explicit fields, readable by the compiler without
// parsing an expression:
//
//   - id: require-mfa
//     type: authentication_strength
//     signal: session.authentication.strength
//     operator: eq
//     value: mfa
//
// CEL format — a single expression, more concise and directly usable by
// runtime PDPs:
//
//   - id: require-mfa
//     type: authentication_strength
//     cel: "session.authentication.strength == 'mfa'"
//
// Both formats may be provided simultaneously. When only the structured form
// is present, CelExpr() derives the equivalent CEL expression automatically.
// When only CEL is present, type is still recommended for compiler coverage
// classification; it can also be inferred from the signal prefix in the
// expression.
//
// operator (structured form): eq | neq | gte | lte | gt | lt | in | not_in
type Condition struct {
	ID       string `yaml:"id"`
	Type     string `yaml:"type,omitempty"`
	Signal   string `yaml:"signal,omitempty"`
	Operator string `yaml:"operator,omitempty"`
	Value    any    `yaml:"value,omitempty"`
	CEL      string `yaml:"cel,omitempty"`
}

// EnforcementConstraints declare what the policy author accepts when Forge
// translates generic intent into target-specific enforcement.
type EnforcementConstraints struct {
	// Nil means not explicitly constrained and is treated permissively by the
	// Config PDP for backwards compatibility. Set false to fail delegated
	// requirements.
	AllowDelegation *bool `yaml:"allowDelegation,omitempty"`

	// Nil means not explicitly constrained and is treated permissively by the
	// Config PDP. Set false to fail partial/downgraded mappings.
	AllowSemanticDowngrade *bool `yaml:"allowSemanticDowngrade,omitempty"`

	// MinimumFidelity may be "low", "medium" or "high".
	MinimumFidelity string `yaml:"minimumFidelity,omitempty"`

	// AllowedDelegationOwners restricts delegated requirement owners.
	AllowedDelegationOwners []string `yaml:"allowedDelegationOwners,omitempty"`

	// AllowedRuntimeActions restricts compensating runtime action IDs.
	AllowedRuntimeActions []string `yaml:"allowedRuntimeActions,omitempty"`

	// RequireApprovalFor documents governance gates that must be externally
	// approved before a durable deployment proceeds.
	RequireApprovalFor []string `yaml:"requireApprovalFor,omitempty"`
}

// CelExpr returns the CEL expression for this condition. If the cel field is
// set it is returned directly. Otherwise an expression is derived from the
// structured signal/operator/value fields. Returns "" if neither form is
// sufficiently populated to produce an expression.
func (c Condition) CelExpr() string {
	if c.CEL != "" {
		return c.CEL
	}
	return deriveCEL(c.Signal, c.Operator, c.Value)
}

// deriveCEL constructs a CEL expression from structured condition fields.
func deriveCEL(signal, operator string, value any) string {
	if signal == "" || operator == "" {
		return ""
	}
	val := celValue(value)
	switch operator {
	case "eq":
		return signal + " == " + val
	case "neq":
		return signal + " != " + val
	case "gte":
		return signal + " >= " + val
	case "lte":
		return signal + " <= " + val
	case "gt":
		return signal + " > " + val
	case "lt":
		return signal + " < " + val
	case "in":
		return signal + " in " + val
	case "not_in":
		return "!(" + signal + " in " + val + ")"
	default:
		return signal + " " + operator + " " + val
	}
}

// celValue formats a condition value as a CEL literal.
func celValue(v any) string {
	if v == nil {
		return "null"
	}
	switch t := v.(type) {
	case string:
		return "'" + t + "'"
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}

// Validate performs basic structural checks on an AccessPolicy.
// It does not validate against registries or capability manifests.
func (p *AccessPolicy) Validate() error {
	snapshot := embeddedRegistrySnapshot()
	schema, hasSchema := accessPolicySchema(snapshot)
	if p.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if p.Kind != KindAccessPolicy {
		return fmt.Errorf("kind must be %s, got %q", KindAccessPolicy, p.Kind)
	}
	if p.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if p.Spec.Subject.Type == "" {
		return fmt.Errorf("spec.subject.type is required")
	}
	if hasSchema {
		subjectSelector, ok := selectorType(schema.SubjectSelectorTypes, p.Spec.Subject.Type)
		if !ok {
			return fmt.Errorf("spec.subject.type %q is not registered for AccessPolicy", p.Spec.Subject.Type)
		}
		if subjectSelector.RequiresRef && strings.TrimSpace(p.Spec.Subject.Ref) == "" {
			return fmt.Errorf("spec.subject.ref is required for subject type %q", p.Spec.Subject.Type)
		}
	}
	if p.Spec.Action == "" {
		return fmt.Errorf("spec.action is required")
	}
	if hasSchema && !policyActionAllowed(schema.Actions, p.Spec.Action) {
		return fmt.Errorf("spec.action %q is not registered for AccessPolicy", p.Spec.Action)
	}
	if p.Spec.Resource.Type == "" {
		return fmt.Errorf("spec.resource.type is required")
	}
	if hasSchema {
		resourceSelector, ok := selectorType(schema.ResourceSelectorTypes, p.Spec.Resource.Type)
		if !ok {
			return fmt.Errorf("spec.resource.type %q is not registered for AccessPolicy", p.Spec.Resource.Type)
		}
		if resourceSelector.RequiresRef && strings.TrimSpace(p.Spec.Resource.Ref) == "" {
			return fmt.Errorf("spec.resource.ref is required for resource type %q", p.Spec.Resource.Type)
		}
	}
	if p.Spec.Effect == "" {
		return fmt.Errorf("spec.effect is required")
	}
	if hasSchema && !policyEffectAllowed(schema.Effects, p.Spec.Effect) {
		return fmt.Errorf("spec.effect %q is not registered for AccessPolicy", p.Spec.Effect)
	}
	if !hasSchema {
		switch p.Spec.Effect {
		case "allow", "deny":
		default:
			return fmt.Errorf("spec.effect must be allow or deny, got %q", p.Spec.Effect)
		}
	}
	for i, c := range p.Spec.Conditions {
		if c.ID == "" {
			return fmt.Errorf("spec.conditions[%d].id is required", i)
		}
		if hasSchema && c.Type != "" && !stringInSet(schema.ConditionTypes, c.Type) {
			return fmt.Errorf("spec.conditions[%d] (%q): type %q is not registered for AccessPolicy", i, c.ID, c.Type)
		}
		// At least one form must be present: CEL expression or structured signal.
		if c.CEL == "" && c.Signal == "" {
			return fmt.Errorf("spec.conditions[%d] (%q): either cel or signal is required", i, c.ID)
		}
		if c.Signal != "" && c.Operator == "" {
			return fmt.Errorf("spec.conditions[%d] (%q): operator is required when signal is set", i, c.ID)
		}
		if c.Signal != "" {
			if !registeredContextKey(snapshot, c.Signal) {
				return fmt.Errorf("spec.conditions[%d] (%q): signal %q is not a registered context key", i, c.ID, c.Signal)
			}
			if hasSchema && !stringInSet(schema.Operators, c.Operator) {
				return fmt.Errorf("spec.conditions[%d] (%q): operator %q is not registered for AccessPolicy", i, c.ID, c.Operator)
			}
		}
		if c.CEL != "" {
			if err := ValidateSafeCEL(c.CEL); err != nil {
				return fmt.Errorf("spec.conditions[%d] (%q): unsafe cel: %w", i, c.ID, err)
			}
		}
	}
	return nil
}

// ValidateSafeCEL applies Kernloom's conservative CEL escape-hatch rules.
// Structured conditions remain preferred; CEL must only read registered context
// keys and must not describe side effects or action emission.
func ValidateSafeCEL(expr string) error {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return fmt.Errorf("expression is empty")
	}
	lower := strings.ToLower(expr)
	for _, token := range []string{";", "\n", "\r", "enforce.", "notify.", "observe.", "delete", "disable", "exec", "system(", "http.", "grpc.", "allow(", "deny("} {
		if strings.Contains(lower, token) {
			return fmt.Errorf("contains forbidden token %q", token)
		}
	}
	if regexp.MustCompile(`(^|[^=!<>])=([^=]|$)`).MatchString(expr) {
		return fmt.Errorf("assignment is not allowed")
	}
	keys := registeredCELKeys()
	for _, key := range celDottedIdentifiers(expr) {
		if !keys[key] {
			return fmt.Errorf("unknown context key %q", key)
		}
	}
	return nil
}

func registeredCELKeys() map[string]bool {
	out := map[string]bool{
		"subject.ref":  true,
		"resource.ref": true,
		"source.ip":    true,
		"source.id":    true,
	}
	snapshot := embeddedRegistrySnapshot()
	for _, key := range snapshot.ContextKeys {
		out[key.ID] = true
	}
	return out
}

func embeddedRegistrySnapshot() contracts.RegistrySnapshot {
	snapshot, err := registries.EmbeddedSnapshot()
	if err != nil {
		return contracts.RegistrySnapshot{}
	}
	return snapshot
}

func accessPolicySchema(snapshot contracts.RegistrySnapshot) (contracts.AccessPolicySchemaEntry, bool) {
	for _, schema := range snapshot.AccessPolicySchemas {
		if schema.WireKind == string(KindAccessPolicy) || schema.ID == "access_policy" {
			return schema, true
		}
	}
	return contracts.AccessPolicySchemaEntry{}, false
}

func selectorType(selectors []contracts.SelectorTypeEntry, id string) (contracts.SelectorTypeEntry, bool) {
	id = normalizePolicyID(id)
	for _, selector := range selectors {
		if normalizePolicyID(selector.ID) == id {
			return selector, true
		}
	}
	return contracts.SelectorTypeEntry{}, false
}

func policyActionAllowed(actions []contracts.PolicyActionEntry, id string) bool {
	id = normalizePolicyID(id)
	for _, action := range actions {
		if normalizePolicyID(action.ID) == id {
			return true
		}
	}
	return false
}

func policyEffectAllowed(effects []contracts.PolicyEffectEntry, id string) bool {
	id = normalizePolicyID(id)
	for _, effect := range effects {
		if normalizePolicyID(effect.ID) == id {
			return true
		}
	}
	return false
}

func stringInSet(values []string, value string) bool {
	value = normalizePolicyID(value)
	for _, candidate := range values {
		if normalizePolicyID(candidate) == value {
			return true
		}
	}
	return false
}

func registeredContextKey(snapshot contracts.RegistrySnapshot, id string) bool {
	for _, key := range snapshot.ContextKeys {
		if key.ID == id {
			return true
		}
	}
	return false
}

func normalizePolicyID(value string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_")
}

func celDottedIdentifiers(expr string) []string {
	expr = stripQuotedCELStrings(expr)
	matches := regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+`).FindAllString(expr, -1)
	seen := map[string]bool{}
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if strings.HasPrefix(match, "duration.") {
			continue
		}
		if !seen[match] {
			seen[match] = true
			out = append(out, match)
		}
	}
	return out
}

func stripQuotedCELStrings(expr string) string {
	re := regexp.MustCompile(`"([^"\\]|\\.)*"|'([^'\\]|\\.)*'`)
	return re.ReplaceAllString(expr, "''")
}

// ParseAccessPolicy parses an AccessPolicy from raw YAML bytes.
func ParseAccessPolicy(data []byte) (*AccessPolicy, error) {
	var p AccessPolicy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing AccessPolicy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid AccessPolicy: %w", err)
	}
	return &p, nil
}

// LoadAccessPolicyFromFile parses an AccessPolicy from a YAML file on disk.
func LoadAccessPolicyFromFile(path string) (*AccessPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return ParseAccessPolicy(data)
}
