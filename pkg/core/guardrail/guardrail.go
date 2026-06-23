// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package guardrail defines authored safety invariants and compiles them into
// the runtime guardrail IR carried by RuntimePolicyPack.
package guardrail

import (
	"fmt"
	"os"
	"strings"

	contracts "github.com/kernloom/kernloom-contracts"
	registries "github.com/kernloom/kernloom-registries"
	"gopkg.in/yaml.v3"
)

const KindGuardrailPolicy = "GuardrailPolicy"

type Policy struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

type Metadata struct {
	Name    string `yaml:"name,omitempty"`
	ID      string `yaml:"id,omitempty"`
	Version string `yaml:"version,omitempty"`
}

type Spec struct {
	Invariants []Invariant `yaml:"invariants"`
}

type Invariant struct {
	ID               string      `yaml:"id"`
	Type             string      `yaml:"type"`
	Subject          Subject     `yaml:"subject,omitempty"`
	ForbiddenActions []string    `yaml:"forbiddenActions,omitempty"`
	AppliesTo        AppliesTo   `yaml:"appliesTo,omitempty"`
	Enforcement      Enforcement `yaml:"enforcement,omitempty"`
}

type Subject struct {
	Type string `yaml:"type,omitempty"`
	Ref  string `yaml:"ref,omitempty"`
}

type AppliesTo struct {
	Resources []string `yaml:"resources,omitempty"`
}

type Enforcement struct {
	ViolationBehavior string `yaml:"violationBehavior,omitempty"`
	UnknownBehavior   string `yaml:"unknownBehavior,omitempty"`
}

func LoadPolicyFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing GuardrailPolicy %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid GuardrailPolicy %s: %w", path, err)
	}
	return &p, nil
}

func (p *Policy) Validate() error {
	snapshot := embeddedSnapshot()
	if p.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if p.Kind != KindGuardrailPolicy {
		return fmt.Errorf("kind must be %s, got %q", KindGuardrailPolicy, p.Kind)
	}
	if p.Metadata.Name == "" && p.Metadata.ID == "" {
		return fmt.Errorf("metadata.name or metadata.id is required")
	}
	if len(p.Spec.Invariants) == 0 {
		return fmt.Errorf("spec.invariants must not be empty")
	}
	for i, inv := range p.Spec.Invariants {
		if inv.ID == "" {
			return fmt.Errorf("spec.invariants[%d].id is required", i)
		}
		if !validGuardrailType(snapshot, inv.Type) {
			return fmt.Errorf("spec.invariants[%d] (%s): unsupported type %q", i, inv.ID, inv.Type)
		}
		if inv.Type != "never" {
			return fmt.Errorf("spec.invariants[%d] (%s): type %q is registered but not supported by this compiler", i, inv.ID, inv.Type)
		}
		if inv.Subject.Type == "" || inv.Subject.Ref == "" {
			return fmt.Errorf("spec.invariants[%d] (%s): subject.type and subject.ref are required", i, inv.ID)
		}
		if !validSubjectType(snapshot, inv.Subject.Type) {
			return fmt.Errorf("spec.invariants[%d] (%s): subject.type %q is not registered", i, inv.ID, inv.Subject.Type)
		}
		if len(inv.ForbiddenActions) == 0 {
			return fmt.Errorf("spec.invariants[%d] (%s): forbiddenActions must not be empty", i, inv.ID)
		}
		if actions := canonicalForbiddenActions(snapshot, inv.ForbiddenActions); len(actions) == 0 {
			return fmt.Errorf("spec.invariants[%d] (%s): forbiddenActions contain no registered runtime actions", i, inv.ID)
		}
	}
	return nil
}

func (p *Policy) RuntimeGuardrails() ([]contracts.RuntimeGuardrail, error) {
	snapshot := embeddedSnapshot()
	out := make([]contracts.RuntimeGuardrail, 0, len(p.Spec.Invariants))
	for _, inv := range p.Spec.Invariants {
		actions := canonicalForbiddenActions(snapshot, inv.ForbiddenActions)
		if len(actions) == 0 {
			return nil, fmt.Errorf("invariant %q has no supported forbidden actions", inv.ID)
		}
		enforcement := inv.Enforcement
		if enforcement.ViolationBehavior == "" {
			enforcement.ViolationBehavior = "reject_action"
		}
		if enforcement.UnknownBehavior == "" {
			enforcement.UnknownBehavior = "reject_hard_action"
		}
		out = append(out, contracts.RuntimeGuardrail{
			ID:   inv.ID,
			Type: inv.Type,
			Subject: contracts.RuntimeGuardrailSubject{
				Type: inv.Subject.Type,
				Ref:  inv.Subject.Ref,
			},
			ForbiddenActions: actions,
			AppliesTo: contracts.RuntimeGuardrailAppliesTo{
				Resources: append([]string(nil), inv.AppliesTo.Resources...),
			},
			Enforcement: contracts.RuntimeGuardrailEnforcement{
				ViolationBehavior: enforcement.ViolationBehavior,
				UnknownBehavior:   enforcement.UnknownBehavior,
			},
			ReasonCodes: []string{"guardrail_" + sanitizeReason(inv.ID)},
		})
	}
	return out, nil
}

func FromNeverTokens(tokens []string) (contracts.RuntimeGuardrail, error) {
	if len(tokens) < 3 {
		return contracts.RuntimeGuardrail{}, fmt.Errorf("never must use '<action> <subject-type> <subject-ref>'")
	}
	subjectIndex := -1
	for i, tok := range tokens {
		if isSubjectType(tok) {
			subjectIndex = i
			break
		}
	}
	if subjectIndex <= 0 || subjectIndex == len(tokens)-1 {
		return contracts.RuntimeGuardrail{}, fmt.Errorf("never must include an action and a typed subject")
	}
	action := strings.Join(tokens[:subjectIndex], "_")
	subjectType := tokens[subjectIndex]
	subjectRef := strings.Join(tokens[subjectIndex+1:], " ")
	return FromNever(action, subjectType, subjectRef)
}

func FromNever(action, subjectType, subjectRef string) (contracts.RuntimeGuardrail, error) {
	snapshot := embeddedSnapshot()
	forbidden := canonicalForbiddenActions(snapshot, []string{action})
	if len(forbidden) == 0 {
		return contracts.RuntimeGuardrail{}, fmt.Errorf("unsupported never action %q", action)
	}
	if subjectType == "" || subjectRef == "" {
		return contracts.RuntimeGuardrail{}, fmt.Errorf("never guardrail requires a typed subject")
	}
	if !validSubjectType(snapshot, subjectType) {
		return contracts.RuntimeGuardrail{}, fmt.Errorf("unsupported never subject type %q", subjectType)
	}
	id := "never-" + sanitizeID(action) + "-" + sanitizeID(subjectRef)
	return contracts.RuntimeGuardrail{
		ID:   id,
		Type: "never",
		Subject: contracts.RuntimeGuardrailSubject{
			Type: subjectType,
			Ref:  subjectRef,
		},
		ForbiddenActions: forbidden,
		Enforcement: contracts.RuntimeGuardrailEnforcement{
			ViolationBehavior: "reject_action",
			UnknownBehavior:   "reject_hard_action",
		},
		ReasonCodes: []string{"guardrail_" + sanitizeReason(id)},
	}, nil
}

func PolicyFromRuntime(name string, guardrails []contracts.RuntimeGuardrail) Policy {
	invariants := make([]Invariant, 0, len(guardrails))
	for _, g := range guardrails {
		invariants = append(invariants, Invariant{
			ID:   g.ID,
			Type: g.Type,
			Subject: Subject{
				Type: g.Subject.Type,
				Ref:  g.Subject.Ref,
			},
			ForbiddenActions: append([]string(nil), g.ForbiddenActions...),
			AppliesTo: AppliesTo{
				Resources: append([]string(nil), g.AppliesTo.Resources...),
			},
			Enforcement: Enforcement{
				ViolationBehavior: g.Enforcement.ViolationBehavior,
				UnknownBehavior:   g.Enforcement.UnknownBehavior,
			},
		})
	}
	return Policy{
		APIVersion: "kernloom.io/v1",
		Kind:       KindGuardrailPolicy,
		Metadata:   Metadata{Name: name},
		Spec:       Spec{Invariants: invariants},
	}
}

func canonicalForbiddenActions(snapshot contracts.RegistrySnapshot, actions []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(action string) {
		action = strings.TrimSpace(action)
		if action == "" || seen[action] || !validRuntimeAction(snapshot, action) {
			return
		}
		seen[action] = true
		out = append(out, action)
	}
	for _, raw := range actions {
		action := strings.ReplaceAll(strings.TrimSpace(raw), " ", "_")
		switch action {
		case "auto_block", "block", "temporary_block":
			add("enforce.traffic.drop")
			add("enforce.access.deny")
			add("enforce.network.quarantine")
			add("enforce.identity.disable")
		case "quarantine", "network_quarantine":
			add("enforce.network.quarantine")
		case "disable_identity", "identity_disable":
			add("enforce.identity.disable")
		case "deny", "network_deny", "network.flow_deny":
			add("enforce.access.deny")
		default:
			if strings.HasPrefix(action, "enforce.") {
				add(action)
			}
		}
	}
	return out
}

func isSubjectType(s string) bool {
	return validSubjectType(embeddedSnapshot(), s)
}

func embeddedSnapshot() contracts.RegistrySnapshot {
	snapshot, err := registries.EmbeddedSnapshot()
	if err != nil {
		return contracts.RegistrySnapshot{}
	}
	return snapshot
}

func validGuardrailType(snapshot contracts.RegistrySnapshot, value string) bool {
	value = normalizeRegistryID(value)
	for _, entry := range snapshot.GuardrailTypes {
		if normalizeRegistryID(entry.ID) == value {
			return true
		}
	}
	return value == "never"
}

func validSubjectType(snapshot contracts.RegistrySnapshot, value string) bool {
	value = normalizeRegistryID(value)
	for _, schema := range snapshot.AccessPolicySchemas {
		if schema.WireKind != contracts.KindAccessPolicy && schema.ID != "access_policy" {
			continue
		}
		for _, selector := range schema.SubjectSelectorTypes {
			if normalizeRegistryID(selector.ID) == value && selector.ID != "any" {
				return true
			}
		}
	}
	switch value {
	case "role", "group", "user", "service_account", "workload", "device_identity", "automation_identity", "external_partner":
		return true
	default:
		return false
	}
}

func validRuntimeAction(snapshot contracts.RegistrySnapshot, action string) bool {
	for _, contract := range snapshot.ActionContracts {
		if contract.ID == action {
			return true
		}
	}
	return false
}

func normalizeRegistryID(value string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_")
}

func sanitizeID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var out strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			out.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			out.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(out.String(), "-")
}

func sanitizeReason(s string) string {
	return strings.ReplaceAll(sanitizeID(s), "-", "_")
}
