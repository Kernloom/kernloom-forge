// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package risk

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// RiskModel is a versioned policy artifact that defines how to compute a
// RiskAssessment from context facts and indicators.
//
// A RiskModel lives in Git and is approved through the PAP process.
// It must be vendor-neutral: no vendor field names appear in model rules.
// Vendor-specific mapping logic belongs in SignalMappings.
//
// Example YAML:
//
//	apiVersion: kernloom.io/risk/v1alpha1
//	kind: RiskModel
//	metadata:
//	  name: enterprise-access-risk
//	  version: 1.2.0
//	  owner: security-architecture
//	spec:
//	  scopeTypes: [subject, device, session]
//	  inputs:
//	    - id: edr_device_unhealthy
//	      source: context
//	      key: device.edr.status
//	      match: unhealthy
//	      baseContribution: 40
//	  output:
//	    range: {min: 0, max: 100}
//	    levels:
//	      low:      [0, 29]
//	      medium:   [30, 59]
//	      high:     [60, 79]
//	      critical: [80, 100]
type RiskModel struct {
	APIVersion string        `yaml:"apiVersion"`
	Kind       string        `yaml:"kind"`
	Metadata   RiskModelMeta `yaml:"metadata"`
	Spec       RiskModelSpec `yaml:"spec"`
}

// RiskModelMeta identifies the risk model.
type RiskModelMeta struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
	Owner   string `yaml:"owner,omitempty"`
}

// RiskModelSpec is the normative body of a RiskModel.
type RiskModelSpec struct {
	// ScopeTypes lists which risk scopes this model can assess.
	ScopeTypes []RiskScope `yaml:"scopeTypes"`

	// Domains groups inputs by risk domain for per-domain reporting.
	// Keys are domain names (e.g. "authentication", "access_behavior").
	// Values define the maximum contribution per domain.
	Domains map[string]DomainConfig `yaml:"domains,omitempty"`

	// Inputs are the scoring rules. Each input contributes positively or
	// negatively to the final score when its condition is met.
	Inputs []RiskModelInput `yaml:"inputs"`

	// Output defines the score range and level thresholds.
	Output RiskModelOutput `yaml:"output"`

	// Validity defines assessment freshness constraints.
	Validity RiskModelValidity `yaml:"validity"`
}

// DomainConfig controls contribution limits for a risk domain.
type DomainConfig struct {
	// MaxContribution caps the total points from this domain.
	MaxContribution int `yaml:"maxContribution"`
}

// RiskModelInput is a single scoring rule. When its condition matches a
// context fact or indicator, it produces a RiskContribution.
type RiskModelInput struct {
	// ID is the unique rule identifier within this model.
	ID string `yaml:"id"`

	// Source declares where to look for the trigger value.
	// Values: "context" (ContextFact key/value), "indicator" (RiskIndicator key),
	// "vendor_assessment" (VendorAssessment key — use sparingly).
	Source string `yaml:"source"`

	// Key is the canonical context key or indicator key to check.
	// Must not use vendor-namespaced names.
	Key string `yaml:"key"`

	// Match is the value (or range) that triggers this rule.
	// For string_enum: exact match (e.g. "unhealthy").
	// For integer/float: range expression (e.g. "> 80").
	// Empty means "key is present with any non-empty value".
	Match any `yaml:"match,omitempty"`

	// Domain places this rule's contribution into a domain bucket for capping.
	Domain string `yaml:"domain,omitempty"`

	// BaseContribution is the raw point value (positive increases risk,
	// negative decreases it — e.g. for strong MFA confirmation).
	BaseContribution int `yaml:"baseContribution"`

	// ConfidenceMode controls how source confidence affects EffectiveValue.
	// "source" = multiply by the fact's confidence.
	// "fixed"  = use 1.0 regardless.
	ConfidenceMode string `yaml:"confidenceMode,omitempty"`

	// Decay controls how the contribution decreases with the age of the input.
	Decay DecayConfig `yaml:"decay,omitempty"`

	// CapPerGroup is the maximum contribution from this rule per correlation group.
	// 0 means no per-group cap.
	CapPerGroup int `yaml:"capPerGroup,omitempty"`
}

// DecayConfig describes time-based confidence decay for a risk input.
type DecayConfig struct {
	// HalfLife is the time after which the freshness factor reaches 0.5.
	// 0 means no decay (full freshness factor always applied).
	HalfLife time.Duration `yaml:"halfLife,omitempty"`
}

// RiskModelOutput defines the numeric range and level thresholds.
type RiskModelOutput struct {
	Range  ScoreRange        `yaml:"range"`
	Levels map[string][2]int `yaml:"levels"` // e.g. "high": [60, 79]
}

// ScoreRange defines valid score boundaries.
type ScoreRange struct {
	Min int `yaml:"min"`
	Max int `yaml:"max"`
}

// RiskModelValidity declares assessment freshness requirements.
type RiskModelValidity struct {
	// TTL is how long a computed assessment is valid.
	TTL time.Duration `yaml:"ttl"`

	// MinConfidence is the minimum confidence for the assessment to be usable.
	MinConfidence float64 `yaml:"minConfidence,omitempty"`

	// MinCompleteness is the minimum completeness for the assessment to be usable.
	MinCompleteness float64 `yaml:"minCompleteness,omitempty"`
}

// RiskCombinationProfile defines how local (KLIQ) and global (Correlate/Forge)
// risk assessments are combined when operating in hybrid mode.
//
// This is Forge's declaration; KLIQ applies it within the permitted local risk mode.
type RiskCombinationProfile struct {
	APIVersion string                 `yaml:"apiVersion"`
	Kind       string                 `yaml:"kind"`
	Metadata   CombinationProfileMeta `yaml:"metadata"`
	Spec       CombinationProfileSpec `yaml:"spec"`
}

// CombinationProfileMeta identifies the combination profile.
type CombinationProfileMeta struct {
	Name string `yaml:"name"`
}

// CombinationProfileSpec is the normative body of a RiskCombinationProfile.
type CombinationProfileSpec struct {
	// LocalMode is the permitted local risk mode for KLIQ.
	// Values: "none", "cached_global", "local_lite", "local_full", "hybrid"
	LocalMode string `yaml:"localMode"`

	// Strategy controls how local and global assessments are merged.
	// Values: "local_only", "global_only", "max", "weighted_average", "restrictive_and"
	Strategy string `yaml:"strategy"`

	// GlobalWeight is the weight of the global assessment in a weighted average (0.0–1.0).
	// Used only when Strategy = "weighted_average".
	GlobalWeight float64 `yaml:"globalWeight,omitempty"`

	// GlobalTTL is how long a cached global assessment remains usable offline.
	GlobalTTL time.Duration `yaml:"globalTTL,omitempty"`

	// OnGlobalExpiry defines behavior when the cached global assessment expires.
	// Values: "use_local_only", "degrade_confidence", "block"
	OnGlobalExpiry string `yaml:"onGlobalExpiry,omitempty"`
}

// Validate performs basic structural checks on a RiskModel.
func (m *RiskModel) Validate() error {
	if m.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if m.Kind != "RiskModel" {
		return fmt.Errorf("kind must be RiskModel, got %q", m.Kind)
	}
	if m.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if m.Metadata.Version == "" {
		return fmt.Errorf("metadata.version is required")
	}
	for i, inp := range m.Spec.Inputs {
		if inp.ID == "" {
			return fmt.Errorf("inputs[%d].id is required", i)
		}
		if inp.Source == "" {
			return fmt.Errorf("inputs[%d] (%s): source is required", i, inp.ID)
		}
		if inp.Key == "" {
			return fmt.Errorf("inputs[%d] (%s): key is required", i, inp.ID)
		}
		// Reject vendor-namespaced keys in model rules.
		for _, vendorPrefix := range []string{"openziti.", "ziti.", "edr.", "idp.", "zscaler."} {
			if len(inp.Key) > len(vendorPrefix) && inp.Key[:len(vendorPrefix)] == vendorPrefix {
				return fmt.Errorf("inputs[%d] (%s): key %q must not use vendor-namespaced names in risk model rules",
					i, inp.ID, inp.Key)
			}
		}
	}
	return nil
}

// LoadModelFromFile parses a RiskModel from a YAML file.
func LoadModelFromFile(path string) (*RiskModel, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return ParseModel(data)
}

// ParseModel parses a RiskModel from raw YAML bytes.
func ParseModel(data []byte) (*RiskModel, error) {
	var m RiskModel
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing RiskModel: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("invalid RiskModel: %w", err)
	}
	return &m, nil
}
