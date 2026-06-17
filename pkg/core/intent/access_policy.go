// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package intent

import (
	"fmt"
	"os"

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
//	      signal: subject.auth_strength
//	      operator: gte
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
	Subject    Subject     `yaml:"subject"`
	Action     string      `yaml:"action"`
	Resource   Resource    `yaml:"resource"`
	Conditions []Condition `yaml:"conditions,omitempty"`
	Effect     string      `yaml:"effect"` // allow | deny
}

// Subject identifies who the policy applies to.
// type: role | group | user | service_account | any
type Subject struct {
	Type string `yaml:"type"`
	Ref  string `yaml:"ref,omitempty"`
}

// Resource identifies what the policy protects.
// type: application_group | service | endpoint | data_class | any
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
//     signal: subject.auth_strength
//     operator: gte
//     value: mfa
//
// CEL format — a single expression, more concise and directly usable by
// runtime PDPs:
//
//   - id: require-mfa
//     type: authentication_strength
//     cel: "subject.auth_strength >= 'mfa'"
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
	if p.Spec.Action == "" {
		return fmt.Errorf("spec.action is required")
	}
	if p.Spec.Resource.Type == "" {
		return fmt.Errorf("spec.resource.type is required")
	}
	switch p.Spec.Effect {
	case "allow", "deny":
	case "":
		return fmt.Errorf("spec.effect is required")
	default:
		return fmt.Errorf("spec.effect must be allow or deny, got %q", p.Spec.Effect)
	}
	for i, c := range p.Spec.Conditions {
		if c.ID == "" {
			return fmt.Errorf("spec.conditions[%d].id is required", i)
		}
		// At least one form must be present: CEL expression or structured signal.
		if c.CEL == "" && c.Signal == "" {
			return fmt.Errorf("spec.conditions[%d] (%q): either cel or signal is required", i, c.ID)
		}
		if c.Signal != "" && c.Operator == "" {
			return fmt.Errorf("spec.conditions[%d] (%q): operator is required when signal is set", i, c.ID)
		}
	}
	return nil
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
