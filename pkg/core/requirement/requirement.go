// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package requirement defines canonical atomic requirements extracted from an
// AccessPolicy. A RequirementSet is the normalized, vendor-neutral list of
// conditions that must be satisfied by one or more targets.
//
// Requirements use dot-notation signal paths as their canonical IDs so that
// the compiler can match them against CapabilityManifests without knowing
// anything about specific vendors.
package requirement

import (
	"fmt"
	"strings"

	"github.com/kernloom/kernloom-forge/pkg/core/intent"
)

// Kind constants identify the category of a requirement so capability matchers
// can quickly filter without inspecting signal paths.
const (
	KindSubjectIdentity = "subject_identity" // who the subject is (role, group)
	KindResourceIdentity = "resource_identity" // what resource is targeted
	KindAuthStrength    = "auth_strength"    // authentication assurance level
	KindRiskLevel       = "risk_level"       // risk score / level
	KindDevicePosture   = "device_posture"   // device compliance / health
	KindSessionContext  = "session_context"  // session-scoped signals
	KindNetworkTuple    = "network_tuple"    // IP/port/protocol conditions
	KindCustom          = "custom"           // any other condition type
)

// Requirement is a single canonical atomic condition extracted from a policy.
// Every field is vendor-neutral; adapters translate these into target-specific
// representations via RequirementMappings.
type Requirement struct {
	// ID is the unique identifier within the RequirementSet, taken from
	// the source condition's id field.
	ID string

	// Kind classifies the requirement for fast capability matching.
	Kind string

	// Signal is the dot-notation context path, e.g. "subject.auth_strength".
	// May be empty when the condition was specified in CEL-only form.
	Signal string

	// Operator is the comparison operator: eq, neq, gte, lte, gt, lt, in, not_in.
	// May be empty when the condition was specified in CEL-only form.
	Operator string

	// Value is the required value to compare against.
	// May be nil when the condition was specified in CEL-only form.
	Value any

	// CEL is the expression for runtime PDPs. Always populated: either from
	// the source condition's cel field or derived from Signal/Operator/Value.
	CEL string

	// ConditionType is the raw type field from the source condition, preserved
	// for documentation and reporting.
	ConditionType string
}

// RequirementSet is the full set of canonical requirements extracted from a
// single AccessPolicy. It also carries the top-level subject, resource and
// effect for context.
type RequirementSet struct {
	// PolicyName is the metadata.name of the source AccessPolicy.
	PolicyName string

	// Subject and Resource are the top-level policy principals, also expressed
	// as requirements so targets can match on them.
	SubjectRequirement  Requirement
	ResourceRequirement Requirement

	// Effect is "allow" or "deny".
	Effect string

	// Conditions holds all extracted condition requirements.
	Conditions []Requirement
}

// All returns every requirement in the set (subject, resource, conditions)
// as a flat slice — convenient for iterating over everything a target must
// satisfy.
func (rs *RequirementSet) All() []Requirement {
	out := make([]Requirement, 0, 2+len(rs.Conditions))
	out = append(out, rs.SubjectRequirement)
	out = append(out, rs.ResourceRequirement)
	out = append(out, rs.Conditions...)
	return out
}

// Extract converts an AccessPolicy into a RequirementSet.
// It never silently drops requirements: if a condition cannot be classified,
// it is placed in KindCustom so it remains visible in reports.
func Extract(p *intent.AccessPolicy) (*RequirementSet, error) {
	if p == nil {
		return nil, fmt.Errorf("policy must not be nil")
	}

	subjectVal := p.Spec.Subject.Type + ":" + p.Spec.Subject.Ref
	resourceVal := p.Spec.Resource.Type + ":" + p.Spec.Resource.Ref

	rs := &RequirementSet{
		PolicyName: p.Metadata.Name,
		Effect:     p.Spec.Effect,
		SubjectRequirement: Requirement{
			ID:            "subject-identity",
			Kind:          KindSubjectIdentity,
			Signal:        "subject.type",
			Operator:      "eq",
			Value:         subjectVal,
			CEL:           "subject.type == '" + p.Spec.Subject.Type + "' && subject.ref == '" + p.Spec.Subject.Ref + "'",
			ConditionType: "subject_identity",
		},
		ResourceRequirement: Requirement{
			ID:            "resource-identity",
			Kind:          KindResourceIdentity,
			Signal:        "resource.type",
			Operator:      "eq",
			Value:         resourceVal,
			CEL:           "resource.type == '" + p.Spec.Resource.Type + "' && resource.ref == '" + p.Spec.Resource.Ref + "'",
			ConditionType: "resource_identity",
		},
	}

	for _, c := range p.Spec.Conditions {
		req := Requirement{
			ID:            c.ID,
			Kind:          classifyCondition(c),
			Signal:        c.Signal,
			Operator:      c.Operator,
			Value:         c.Value,
			CEL:           c.CelExpr(),
			ConditionType: c.Type,
		}
		rs.Conditions = append(rs.Conditions, req)
	}

	return rs, nil
}

// classifyCondition maps a Condition to a canonical Kind.
// It first tries the explicit type field; if that is absent or unrecognised,
// it falls back to deriving the kind from the signal prefix.
func classifyCondition(c intent.Condition) string {
	if kind := kindFromType(c.Type); kind != KindCustom {
		return kind
	}
	return kindFromSignal(c.Signal)
}

// kindFromType maps the explicit type string to a Kind constant.
func kindFromType(t string) string {
	switch strings.ToLower(t) {
	case "authentication_strength", "auth_strength", "mfa":
		return KindAuthStrength
	case "risk_level", "risk":
		return KindRiskLevel
	case "device_posture", "device_compliance":
		return KindDevicePosture
	case "session_location", "session_context":
		return KindSessionContext
	case "network_tuple", "ip_range", "port", "protocol":
		return KindNetworkTuple
	default:
		return KindCustom
	}
}

// kindFromSignal derives a Kind from the dot-notation signal path prefix.
// This is the fallback when the type field is absent or unrecognised.
func kindFromSignal(signal string) string {
	switch {
	case strings.HasPrefix(signal, "subject.auth"):
		return KindAuthStrength
	case strings.HasPrefix(signal, "subject.risk"):
		return KindRiskLevel
	case strings.HasPrefix(signal, "subject."):
		return KindSubjectIdentity
	case strings.HasPrefix(signal, "device.posture"), strings.HasPrefix(signal, "device.compliance"):
		return KindDevicePosture
	case strings.HasPrefix(signal, "device."):
		return KindDevicePosture
	case strings.HasPrefix(signal, "session."):
		return KindSessionContext
	case strings.HasPrefix(signal, "network."),
		strings.HasPrefix(signal, "ip."),
		strings.HasPrefix(signal, "port."),
		strings.HasPrefix(signal, "proto."):
		return KindNetworkTuple
	case strings.HasPrefix(signal, "resource."):
		return KindResourceIdentity
	default:
		return KindCustom
	}
}

// String returns a human-readable summary of the requirement.
func (r Requirement) String() string {
	if r.CEL != "" {
		return fmt.Sprintf("[%s] %s", r.Kind, r.CEL)
	}
	return fmt.Sprintf("[%s] %s %s %v", r.Kind, r.Signal, r.Operator, r.Value)
}
