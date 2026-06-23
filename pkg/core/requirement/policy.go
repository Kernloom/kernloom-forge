// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package requirement

import (
	"fmt"
	"os"
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom-forge/pkg/core/intent"
	registries "github.com/kernloom/kernloom-registries"
	"gopkg.in/yaml.v3"
)

const (
	KindRequirementPolicy       = "RequirementPolicy"
	KindCapabilityRequirement   = "CapabilityRequirement"
	MissingContextDeny          = "deny"
	MissingContextNotMatch      = "not_match"
	MissingContextDegradeAlert  = "degrade_to_alert"
	MissingContextRequireReview = "require_review"
	MissingContextFail          = "fail_validation"
	MissingContextRejectHard    = "reject_hard_action"
)

type Policy struct {
	APIVersion string                `yaml:"apiVersion"`
	Kind       string                `yaml:"kind"`
	Metadata   intent.PolicyMetadata `yaml:"metadata"`
	Spec       PolicySpec            `yaml:"spec"`
}

type PolicySpec struct {
	Requirements RequirementExpression `yaml:"requirements"`
}

type RequirementExpression struct {
	All []RequirementCondition `yaml:"all,omitempty"`
}

type RequirementCondition struct {
	ID                     string               `yaml:"id"`
	Type                   string               `yaml:"type,omitempty"`
	Signal                 string               `yaml:"signal,omitempty"`
	Operator               string               `yaml:"operator,omitempty"`
	Value                  any                  `yaml:"value,omitempty"`
	CEL                    string               `yaml:"cel,omitempty"`
	Freshness              FreshnessRequirement `yaml:"freshness,omitempty"`
	MinConfidence          float64              `yaml:"minConfidence,omitempty"`
	MissingContext         string               `yaml:"missingContext,omitempty"`
	InsufficientConfidence string               `yaml:"insufficientConfidence,omitempty"`
}

type FreshnessRequirement struct {
	MaxAge  string `yaml:"maxAge,omitempty"`
	Require bool   `yaml:"require,omitempty"`
}

type CapabilityRequirement struct {
	APIVersion string                    `yaml:"apiVersion"`
	Kind       string                    `yaml:"kind"`
	Metadata   CapabilityRequirementMeta `yaml:"metadata"`
	Spec       CapabilityRequirementSpec `yaml:"spec"`
}

type CapabilityRequirementMeta struct {
	Name string `yaml:"name,omitempty"`
	ID   string `yaml:"id,omitempty"`
}

type CapabilityRequirementSpec struct {
	Required            []CapabilityRequirementItem `yaml:"required,omitempty"`
	ForbiddenDowngrades []ForbiddenDowngrade        `yaml:"forbiddenDowngrades,omitempty"`
	GapHandling         []GapHandlingRule           `yaml:"gapHandling,omitempty"`
}

type CapabilityRequirementItem struct {
	Capability  string              `yaml:"capability,omitempty"`
	Context     string              `yaml:"context,omitempty"`
	Feature     string              `yaml:"feature,omitempty"`
	Granularity GranularitySelector `yaml:"granularity,omitempty"`
}

type GranularitySelector struct {
	Subject  []string `yaml:"subject,omitempty"`
	Resource []string `yaml:"resource,omitempty"`
}

type ForbiddenDowngrade struct {
	From string   `yaml:"from"`
	To   string   `yaml:"to"`
	For  []string `yaml:"for,omitempty"`
}

type GapHandlingRule struct {
	Behavior string `yaml:"behavior"`
	Gap      string `yaml:"gap"`
}

func PolicyFromConditions(name string, metadata intent.PolicyMetadata, conditions []intent.Condition) Policy {
	reqs := make([]RequirementCondition, 0, len(conditions))
	freshness := defaultFreshnessByContext()
	for _, c := range conditions {
		req := RequirementCondition{
			ID:                     c.ID,
			Type:                   c.Type,
			Signal:                 c.Signal,
			Operator:               c.Operator,
			Value:                  c.Value,
			CEL:                    c.CEL,
			MissingContext:         MissingContextDeny,
			InsufficientConfidence: MissingContextDeny,
		}
		if maxAge := freshness[c.Signal]; maxAge != "" {
			req.Freshness = FreshnessRequirement{MaxAge: maxAge, Require: true}
		}
		reqs = append(reqs, req)
	}
	if name == "" {
		name = metadata.Name + "-requirements"
	}
	metadata.Name = name
	return Policy{
		APIVersion: "kernloom.io/v1",
		Kind:       KindRequirementPolicy,
		Metadata:   metadata,
		Spec:       PolicySpec{Requirements: RequirementExpression{All: reqs}},
	}
}

func LoadPolicyFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing RequirementPolicy %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid RequirementPolicy %s: %w", path, err)
	}
	return &p, nil
}

func (p *Policy) Validate() error {
	if p.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if p.Kind != KindRequirementPolicy {
		return fmt.Errorf("kind must be %s, got %q", KindRequirementPolicy, p.Kind)
	}
	if p.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if len(p.Spec.Requirements.All) == 0 {
		return fmt.Errorf("spec.requirements.all must not be empty")
	}
	snapshot, err := registries.EmbeddedSnapshot()
	if err != nil {
		return fmt.Errorf("load registry snapshot: %w", err)
	}
	contextKeys := contextKeyIndex(snapshot)
	for i, req := range p.Spec.Requirements.All {
		if req.ID == "" {
			return fmt.Errorf("spec.requirements.all[%d].id is required", i)
		}
		if req.CEL == "" && req.Signal == "" {
			return fmt.Errorf("spec.requirements.all[%d] (%s): cel or signal is required", i, req.ID)
		}
		if req.CEL != "" {
			if err := intent.ValidateSafeCEL(req.CEL); err != nil {
				return fmt.Errorf("spec.requirements.all[%d] (%s): unsafe cel: %w", i, req.ID, err)
			}
		}
		if req.Signal != "" {
			key, ok := contextKeys[req.Signal]
			if !ok {
				return fmt.Errorf("spec.requirements.all[%d] (%s): unknown context key %q", i, req.ID, req.Signal)
			}
			if req.Operator == "" {
				return fmt.Errorf("spec.requirements.all[%d] (%s): operator is required", i, req.ID)
			}
			if err := validateRegisteredValue(key, req.Value); err != nil {
				return fmt.Errorf("spec.requirements.all[%d] (%s): %w", i, req.ID, err)
			}
		}
		if req.MissingContext == "" {
			return fmt.Errorf("spec.requirements.all[%d] (%s): missingContext is required", i, req.ID)
		}
		if !validMissingContextBehavior(snapshot, req.MissingContext) {
			return fmt.Errorf("spec.requirements.all[%d] (%s): unsupported missingContext %q", i, req.ID, req.MissingContext)
		}
		if req.InsufficientConfidence != "" && !validMissingContextBehavior(snapshot, req.InsufficientConfidence) {
			return fmt.Errorf("spec.requirements.all[%d] (%s): unsupported insufficientConfidence %q", i, req.ID, req.InsufficientConfidence)
		}
		if req.MinConfidence < 0 || req.MinConfidence > 1 {
			return fmt.Errorf("spec.requirements.all[%d] (%s): minConfidence must be between 0 and 1", i, req.ID)
		}
		if req.MinConfidence > 0 && req.InsufficientConfidence == "" {
			return fmt.Errorf("spec.requirements.all[%d] (%s): insufficientConfidence is required when minConfidence is set", i, req.ID)
		}
		if req.Freshness.MaxAge != "" {
			if _, err := time.ParseDuration(req.Freshness.MaxAge); err != nil {
				return fmt.Errorf("spec.requirements.all[%d] (%s): freshness.maxAge: %w", i, req.ID, err)
			}
		}
	}
	return nil
}

func (p *Policy) Conditions() []intent.Condition {
	out := make([]intent.Condition, 0, len(p.Spec.Requirements.All))
	for _, req := range p.Spec.Requirements.All {
		out = append(out, intent.Condition{
			ID:       req.ID,
			Type:     req.Type,
			Signal:   req.Signal,
			Operator: req.Operator,
			Value:    req.Value,
			CEL:      req.CEL,
		})
	}
	return out
}

func ExtractFromPolicies(access *intent.AccessPolicy, policies []Policy) (*RequirementSet, error) {
	if len(policies) == 0 {
		return Extract(access)
	}
	clone := *access
	clone.Spec.Conditions = nil
	for _, p := range policies {
		clone.Spec.Conditions = append(clone.Spec.Conditions, p.Conditions()...)
	}
	return Extract(&clone)
}

func LoadCapabilityRequirementFromFile(path string) (*CapabilityRequirement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var req CapabilityRequirement
	if err := yaml.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("parsing CapabilityRequirement %s: %w", path, err)
	}
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid CapabilityRequirement %s: %w", path, err)
	}
	return &req, nil
}

func (req *CapabilityRequirement) Validate() error {
	if req.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if req.Kind != KindCapabilityRequirement {
		return fmt.Errorf("kind must be %s, got %q", KindCapabilityRequirement, req.Kind)
	}
	if req.Metadata.Name == "" && req.Metadata.ID == "" {
		return fmt.Errorf("metadata.name or metadata.id is required")
	}
	if len(req.Spec.Required) == 0 && len(req.Spec.GapHandling) == 0 {
		return fmt.Errorf("spec.required or spec.gapHandling is required")
	}
	snapshot, err := registries.EmbeddedSnapshot()
	if err != nil {
		return fmt.Errorf("load registry snapshot: %w", err)
	}
	contextKeys := contextKeyIndex(snapshot)
	capabilities := capabilityIndex(snapshot)
	granularities := granularityIndex(snapshot)
	for i, item := range req.Spec.Required {
		if item.Context == "" && item.Capability == "" && item.Feature == "" {
			return fmt.Errorf("spec.required[%d] requires context, capability or feature", i)
		}
		if item.Context != "" {
			if _, ok := contextKeys[item.Context]; !ok {
				return fmt.Errorf("spec.required[%d]: unknown context key %q", i, item.Context)
			}
		}
		if item.Capability != "" {
			if _, ok := capabilities[item.Capability]; !ok {
				return fmt.Errorf("spec.required[%d]: unknown capability %q", i, item.Capability)
			}
		}
		for _, granularity := range append(append([]string{}, item.Granularity.Subject...), item.Granularity.Resource...) {
			if _, ok := granularities[granularity]; !ok {
				return fmt.Errorf("spec.required[%d]: unknown granularity %q", i, granularity)
			}
		}
	}
	for i, downgrade := range req.Spec.ForbiddenDowngrades {
		if downgrade.From == "" || downgrade.To == "" {
			return fmt.Errorf("spec.forbiddenDowngrades[%d] requires from and to", i)
		}
		if _, ok := granularities[downgrade.From]; !ok {
			return fmt.Errorf("spec.forbiddenDowngrades[%d]: unknown from granularity %q", i, downgrade.From)
		}
		if _, ok := granularities[downgrade.To]; !ok {
			return fmt.Errorf("spec.forbiddenDowngrades[%d]: unknown to granularity %q", i, downgrade.To)
		}
	}
	for i, gap := range req.Spec.GapHandling {
		if gap.Behavior == "" || gap.Gap == "" {
			return fmt.Errorf("spec.gapHandling[%d] requires behavior and gap", i)
		}
		if !validGapBehavior(snapshot, gap.Behavior) {
			return fmt.Errorf("spec.gapHandling[%d]: unsupported behavior %q", i, gap.Behavior)
		}
		if !validGapID(snapshot, gap.Gap) {
			return fmt.Errorf("spec.gapHandling[%d]: unsupported gap %q", i, gap.Gap)
		}
	}
	return nil
}

func contextKeyIndex(snapshot contracts.RegistrySnapshot) map[string]contracts.ContextKeyEntry {
	out := map[string]contracts.ContextKeyEntry{}
	for _, key := range snapshot.ContextKeys {
		out[key.ID] = key
	}
	return out
}

func capabilityIndex(snapshot contracts.RegistrySnapshot) map[string]contracts.CapabilityEntry {
	out := map[string]contracts.CapabilityEntry{}
	for _, capability := range snapshot.Capabilities {
		out[capability.ID] = capability
	}
	return out
}

func granularityIndex(snapshot contracts.RegistrySnapshot) map[string]contracts.GranularityEntry {
	out := map[string]contracts.GranularityEntry{}
	for _, granularity := range snapshot.Granularities {
		out[granularity.ID] = granularity
	}
	return out
}

func defaultFreshnessByContext() map[string]string {
	out := map[string]string{}
	snapshot, err := registries.EmbeddedSnapshot()
	if err != nil {
		return out
	}
	for _, key := range snapshot.ContextKeys {
		if key.DefaultTTL != "" {
			out[key.ID] = key.DefaultTTL
		}
	}
	return out
}

func validateRegisteredValue(key contracts.ContextKeyEntry, value any) error {
	if len(key.Values) == 0 || value == nil {
		return nil
	}
	allowed := map[string]bool{}
	for _, v := range key.Values {
		allowed[v] = true
	}
	switch v := value.(type) {
	case string:
		if !allowed[v] {
			return fmt.Errorf("value %q is not allowed for context key %q", v, key.ID)
		}
	case []string:
		for _, item := range v {
			if !allowed[item] {
				return fmt.Errorf("value %q is not allowed for context key %q", item, key.ID)
			}
		}
	case []any:
		for _, item := range v {
			s := fmt.Sprint(item)
			if !allowed[s] {
				return fmt.Errorf("value %q is not allowed for context key %q", s, key.ID)
			}
		}
	}
	return nil
}

func validMissingContextBehavior(snapshot contracts.RegistrySnapshot, value string) bool {
	if vocabularyContains(snapshot.MissingContextBehaviors, value, "") {
		return true
	}
	if len(snapshot.MissingContextBehaviors) > 0 {
		return false
	}
	switch value {
	case MissingContextDeny, MissingContextNotMatch, MissingContextDegradeAlert, MissingContextRequireReview, MissingContextFail, MissingContextRejectHard:
		return true
	default:
		return false
	}
}

func validGapBehavior(snapshot contracts.RegistrySnapshot, value string) bool {
	value = strings.ReplaceAll(strings.TrimSpace(value), "-", "_")
	if vocabularyContains(snapshot.GapHandlingBehaviors, value, "CapabilityRequirement") {
		return true
	}
	if len(snapshot.GapHandlingBehaviors) > 0 {
		return false
	}
	switch value {
	case "fail", "fail_closed", "require_approval", "require_review", "degrade_to_alert", "warn":
		return true
	default:
		return false
	}
}

func vocabularyContains(entries []contracts.PolicyVocabularyEntry, value, appliesTo string) bool {
	value = strings.ReplaceAll(strings.TrimSpace(value), "-", "_")
	for _, entry := range entries {
		if strings.ReplaceAll(strings.TrimSpace(entry.ID), "-", "_") != value {
			continue
		}
		if appliesTo == "" || len(entry.AppliesTo) == 0 {
			return true
		}
		for _, item := range entry.AppliesTo {
			if item == appliesTo {
				return true
			}
		}
	}
	return false
}

func validGapID(snapshot contracts.RegistrySnapshot, value string) bool {
	value = strings.ReplaceAll(strings.TrimSpace(value), "-", "_")
	for _, gapType := range snapshot.GapTypes {
		if strings.ReplaceAll(strings.TrimSpace(gapType.ID), "-", "_") == value {
			return true
		}
	}
	if len(snapshot.GapTypes) > 0 {
		return false
	}
	switch value {
	case "missing_context", "unsupported_access_semantics", "identity_to_ip_downgrade",
		"granularity_gap", "semantic_downgrade", "enforcement_gap", "context_gap",
		"fidelity_gap", "delegation_gap", "observability_gap", "revert_gap", "audit_gap":
		return true
	default:
		return false
	}
}
