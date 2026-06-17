// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package risk defines Kernloom's vendor-neutral risk assessment model.
//
// The Risk Model turns evidence and context into versioned, scoped and
// explainable risk assessments.
//
// Core invariants:
//   - Risk assessment and policy decision are separate concerns.
//   - Risk is scoped to an entity or relationship; no mandatory global score.
//   - Vendor risk remains vendor-native evidence unless explicitly normalized.
//   - Every assessment is versioned, time-bounded and explainable.
//   - Confidence and completeness are separate from score/level.
//   - Missing and stale inputs are explicit.
//   - The Risk Engine has no adapter/PEP dependency and never enforces.
//   - The MVP uses deterministic, auditable models — not opaque ML.
//
// Processing stages:
//
//	Observations + ContextFacts + Signals
//	   → Risk Indicators
//	   → Risk Contributions
//	   → Risk Assessment
//	   → PDP (decision, not risk engine)
package risk

import (
	"time"
)

// RiskScope classifies what kind of entity a risk assessment covers.
type RiskScope string

const (
	RiskScopeSubject   RiskScope = "subject"
	RiskScopeDevice    RiskScope = "device"
	RiskScopeSession   RiskScope = "session"
	RiskScopeResource  RiskScope = "resource"
	RiskScopeWorkload  RiskScope = "workload"
	RiskScopeEdge      RiskScope = "communication_edge"
	RiskScopeNetSource RiskScope = "network_source"
	RiskScopeTarget    RiskScope = "target_platform"
)

// RiskLevel is an ordered severity level derived from the numeric score.
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
	RiskLevelUnknown  RiskLevel = "unknown"
)

// ScopeRef identifies the entity being assessed.
//
// Type examples: "subject", "device", "session"
// Ref  examples: "subject:alice@example.com", "device:device-abc"
type ScopeRef struct {
	Type string `yaml:"type" json:"type"`
	Ref  string `yaml:"ref"  json:"ref"`
}

// ModelRef identifies the risk model that produced an assessment.
type ModelRef struct {
	ID      string `yaml:"id"      json:"id"`
	Version string `yaml:"version" json:"version"`
	Owner   string `yaml:"owner,omitempty" json:"owner,omitempty"`
	// PolicyHash is the hash of the model definition file at compile time.
	PolicyHash string `yaml:"policyHash,omitempty" json:"policyHash,omitempty"`
}

// DomainScore is the per-domain breakdown within an assessment.
// Domains are defined in the RiskModel (e.g. "authentication", "access_behavior").
type DomainScore struct {
	Score      int     `yaml:"score"      json:"score"`
	Confidence float64 `yaml:"confidence" json:"confidence"`
}

// ContributionRef is a lightweight reference to a RiskContribution.
type ContributionRef struct {
	// Ref is the contribution ID or rule ID.
	Ref string `yaml:"ref" json:"ref"`
	// EffectiveValue is the score contribution after all factors are applied.
	EffectiveValue float64 `yaml:"effectiveValue" json:"effectiveValue"`
}

// RiskAssessment is the output of a Risk Engine for a specific entity and scope.
//
// It is versioned, time-bounded and fully explainable. The PDP consumes
// RiskAssessments but cannot modify them.
//
// Example YAML:
//
//	apiVersion: kernloom.io/risk/v1alpha1
//	kind: RiskAssessment
//	metadata:
//	  id: risk-987
//	spec:
//	  scope:
//	    type: subject
//	    ref: subject:alice@example.com
//	  score: 78
//	  level: high
//	  confidence: 0.84
//	  completeness: 0.75
//	  model:
//	    id: enterprise-access-risk
//	    version: 1.2.0
type RiskAssessment struct {
	APIVersion string             `yaml:"apiVersion" json:"apiVersion"`
	Kind       string             `yaml:"kind"       json:"kind"`
	Metadata   AssessmentMetadata `yaml:"metadata"   json:"metadata"`
	Spec       AssessmentSpec     `yaml:"spec"       json:"spec"`
}

// AssessmentMetadata identifies the assessment.
type AssessmentMetadata struct {
	ID string `yaml:"id" json:"id"`
}

// AssessmentSpec is the normative body of a RiskAssessment.
type AssessmentSpec struct {
	// Scope identifies what is being assessed.
	Scope ScopeRef `yaml:"scope" json:"scope"`

	// Score is the numeric risk score (0–100).
	Score int `yaml:"score" json:"score"`

	// Level is the human-readable risk level derived from Score.
	Level RiskLevel `yaml:"level" json:"level"`

	// Confidence is how reliable the assessment is (0.0–1.0).
	// Low confidence may be caused by missing or stale inputs.
	Confidence float64 `yaml:"confidence" json:"confidence"`

	// Completeness is the fraction of required inputs that were available (0.0–1.0).
	Completeness float64 `yaml:"completeness" json:"completeness"`

	// Model identifies which model produced this assessment.
	Model ModelRef `yaml:"model" json:"model"`

	// CalculatedAt is when the Risk Engine produced this assessment.
	CalculatedAt time.Time `yaml:"calculatedAt" json:"calculatedAt"`

	// ValidUntil is when this assessment expires.
	ValidUntil time.Time `yaml:"validUntil" json:"validUntil"`

	// Domains provides per-domain score breakdowns (key = domain name).
	Domains map[string]DomainScore `yaml:"domains,omitempty" json:"domains,omitempty"`

	// Contributors are the score contributions from individual model rules.
	Contributors []ContributionRef `yaml:"contributors,omitempty" json:"contributors,omitempty"`

	// MissingInputs lists canonical context keys that were required but unavailable.
	MissingInputs []string `yaml:"missingInputs,omitempty" json:"missingInputs,omitempty"`

	// Limitations describes known constraints or gaps in this assessment.
	Limitations []string `yaml:"limitations,omitempty" json:"limitations,omitempty"`

	// ReasonCodes are machine-readable reasons (e.g. "SERVICE_ENUMERATION", "DEVICE_UNHEALTHY").
	ReasonCodes []string `yaml:"reasonCodes,omitempty" json:"reasonCodes,omitempty"`

	// EvidenceRefs link to indicators, vendor assessments, or observations.
	EvidenceRefs []string `yaml:"evidenceRefs,omitempty" json:"evidenceRefs,omitempty"`
}

// IsExpired returns true if the assessment has passed its validity window.
func (a *RiskAssessment) IsExpired() bool {
	return !a.Spec.ValidUntil.IsZero() && time.Now().After(a.Spec.ValidUntil)
}

// IsUsable returns true when the assessment is not expired and has sufficient
// confidence and completeness to support a policy decision.
func (a *RiskAssessment) IsUsable(minConfidence, minCompleteness float64) bool {
	if a.IsExpired() {
		return false
	}
	return a.Spec.Confidence >= minConfidence && a.Spec.Completeness >= minCompleteness
}

// RiskIndicator is a normalised, security-relevant interpretation of a fact or signal.
// It is an intermediate step between raw observations and a Risk Contribution.
//
// Example: "subject.behavior.service_enumeration detected with confidence 0.87"
type RiskIndicator struct {
	APIVersion string            `yaml:"apiVersion" json:"apiVersion"`
	Kind       string            `yaml:"kind"       json:"kind"`
	Metadata   IndicatorMetadata `yaml:"metadata"   json:"metadata"`
	Spec       IndicatorSpec     `yaml:"spec"       json:"spec"`
}

// IndicatorMetadata identifies the indicator.
type IndicatorMetadata struct {
	ID string `yaml:"id" json:"id"`
}

// IndicatorSpec is the normative body of a RiskIndicator.
type IndicatorSpec struct {
	// Key is the canonical indicator key (e.g. "subject.behavior.service_enumeration").
	// Must use canonical Kernloom vocabulary, not vendor-specific names.
	Key string `yaml:"key" json:"key"`

	// Scope identifies which entity this indicator applies to.
	Scope ScopeRef `yaml:"scope" json:"scope"`

	// State describes the indicator status: "detected", "cleared", "suspected".
	State string `yaml:"state" json:"state"`

	// Severity: "low", "medium", "high", "critical".
	Severity string `yaml:"severity" json:"severity"`

	// Confidence is the reliability of this indicator (0.0–1.0).
	Confidence float64 `yaml:"confidence" json:"confidence"`

	// ObservedAt is when the underlying signal or evidence was observed.
	ObservedAt time.Time `yaml:"observedAt" json:"observedAt"`

	// ValidUntil is when this indicator expires.
	ValidUntil time.Time `yaml:"validUntil" json:"validUntil"`

	// EvidenceRefs link to observations, signals or vendor assessments.
	EvidenceRefs []string `yaml:"evidenceRefs,omitempty" json:"evidenceRefs,omitempty"`
}

// RiskContribution is a model-specific input to a RiskAssessment.
// Each model rule produces one contribution when its conditions are met.
type RiskContribution struct {
	APIVersion string           `yaml:"apiVersion" json:"apiVersion"`
	Kind       string           `yaml:"kind"       json:"kind"`
	Spec       ContributionSpec `yaml:"spec"       json:"spec"`
}

// ContributionSpec is the normative body of a RiskContribution.
type ContributionSpec struct {
	// ModelRef identifies which risk model rule produced this contribution.
	ModelRef ModelRef `yaml:"modelRef" json:"modelRef"`

	// RuleID is the specific rule within the model.
	RuleID string `yaml:"ruleId" json:"ruleId"`

	// Scope identifies the assessed entity.
	Scope ScopeRef `yaml:"scope" json:"scope"`

	// IndicatorRef links to the indicator that triggered this contribution.
	IndicatorRef string `yaml:"indicatorRef,omitempty" json:"indicatorRef,omitempty"`

	// ContextKey is the context key that triggered this contribution (for context-based rules).
	ContextKey string `yaml:"contextKey,omitempty" json:"contextKey,omitempty"`

	// BaseValue is the raw point contribution before factors.
	BaseValue int `yaml:"baseValue" json:"baseValue"`

	// Direction: "increase" (adds risk) or "decrease" (reduces risk).
	Direction string `yaml:"direction" json:"direction"`

	// ConfidenceFactor is derived from the input's confidence.
	ConfidenceFactor float64 `yaml:"confidenceFactor" json:"confidenceFactor"`

	// FreshnessFactor is derived from the input's age relative to its TTL.
	FreshnessFactor float64 `yaml:"freshnessFactor" json:"freshnessFactor"`

	// EffectiveValue = BaseValue × ConfidenceFactor × FreshnessFactor.
	EffectiveValue float64 `yaml:"effectiveValue" json:"effectiveValue"`
}

// LevelFromScore derives a RiskLevel from a numeric score 0–100.
// Thresholds match the enterprise-access-risk model defaults.
func LevelFromScore(score int) RiskLevel {
	switch {
	case score < 0:
		return RiskLevelUnknown
	case score <= 29:
		return RiskLevelLow
	case score <= 59:
		return RiskLevelMedium
	case score <= 79:
		return RiskLevelHigh
	default:
		return RiskLevelCritical
	}
}
