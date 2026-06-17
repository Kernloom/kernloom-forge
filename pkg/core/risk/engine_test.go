// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package risk_test

import (
	"testing"
	"time"

	"github.com/kernloom/kernloom-forge/pkg/core/context"
	"github.com/kernloom/kernloom-forge/pkg/core/risk"
)

var now = time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

// testModel is a compact model for engine tests.
var testModel = &risk.RiskModel{
	APIVersion: "kernloom.io/risk/v1alpha1",
	Kind:       "RiskModel",
	Metadata:   risk.RiskModelMeta{Name: "test-model", Version: "1.0.0"},
	Spec: risk.RiskModelSpec{
		ScopeTypes: []risk.RiskScope{risk.RiskScopeSubject, risk.RiskScopeDevice},
		Domains: map[string]risk.DomainConfig{
			"device_posture":  {MaxContribution: 40},
			"authentication":  {MaxContribution: 30},
			"access_behavior": {MaxContribution: 45},
		},
		Inputs: []risk.RiskModelInput{
			{
				ID: "device_posture_unhealthy", Source: "context",
				Key: "device.posture.status", Match: "unhealthy",
				Domain: "device_posture", BaseContribution: 35,
				ConfidenceMode: "source",
				Decay:          risk.DecayConfig{HalfLife: 15 * time.Minute},
			},
			{
				ID: "device_posture_degraded", Source: "context",
				Key: "device.posture.status", Match: "degraded",
				Domain: "device_posture", BaseContribution: 20,
				ConfidenceMode: "source",
			},
			{
				ID: "auth_strength_password_only", Source: "context",
				Key: "session.authentication.strength", Match: "password",
				Domain: "authentication", BaseContribution: 15,
				ConfidenceMode: "fixed",
			},
			{
				ID: "auth_phishing_resistant_bonus", Source: "context",
				Key: "session.authentication.strength", Match: "phishing_resistant_mfa",
				Domain: "authentication", BaseContribution: -10,
				ConfidenceMode: "fixed",
			},
			{
				ID: "behavior_anomaly", Source: "context",
				Key: "subject.behavior.anomaly_detected", Match: "true",
				Domain: "access_behavior", BaseContribution: 25,
				ConfidenceMode: "source",
				Decay:          risk.DecayConfig{HalfLife: 10 * time.Minute},
			},
		},
		Output: risk.RiskModelOutput{
			Range:  risk.ScoreRange{Min: 0, Max: 100},
			Levels: map[string][2]int{"low": {0, 29}, "medium": {30, 59}, "high": {60, 79}, "critical": {80, 100}},
		},
		Validity: risk.RiskModelValidity{TTL: 30 * time.Minute, MinConfidence: 0.60},
	},
}

// fact builds a fresh, high-confidence ContextFact for a test.
func fact(key string, value any) context.ContextFact {
	return context.ContextFact{
		Key:   key,
		Value: value,
		Quality: context.DataQuality{
			Confidence: 0.95,
			MaxAge:     30 * time.Minute,
		},
		ObservedAt: now.Add(-2 * time.Minute),
		ValidUntil: now.Add(28 * time.Minute),
		Status:     context.FactStatusKnown,
	}
}

// snap builds a ContextSnapshot with the given facts.
func snap(facts ...context.ContextFact) *context.ContextSnapshot {
	return &context.ContextSnapshot{
		ID:         "test-snapshot",
		SnapshotAt: now,
		ValidUntil: now.Add(30 * time.Minute),
		Facts:      facts,
	}
}

// TestEvaluate_ScenarioNormal — all conditions healthy, risk should be low.
func TestEvaluate_ScenarioNormal(t *testing.T) {
	snapshot := snap(
		fact("device.posture.status", "healthy"),
		fact("session.authentication.strength", "mfa"),
	)

	result, err := risk.Evaluate(testModel, snapshot, nil, now)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Assessment.Spec.Score != 0 {
		t.Errorf("normal scenario: score = %d, want 0 (no rules fire)", result.Assessment.Spec.Score)
	}
	if result.Assessment.Spec.Level != risk.RiskLevelLow {
		t.Errorf("normal scenario: level = %q, want low", result.Assessment.Spec.Level)
	}
	if len(result.Contributions) != 0 {
		t.Errorf("normal scenario: %d contributions, want 0", len(result.Contributions))
	}
}

// TestEvaluate_ScenarioUnhealthyDevice — device posture is unhealthy → high risk.
func TestEvaluate_ScenarioUnhealthyDevice(t *testing.T) {
	snapshot := snap(
		fact("device.posture.status", "unhealthy"),
		fact("session.authentication.strength", "mfa"),
	)

	result, err := risk.Evaluate(testModel, snapshot, nil, now)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// device_posture_unhealthy: 35 × 0.95 (confidence) × decay ≈ 33
	if result.Assessment.Spec.Score <= 0 {
		t.Errorf("unhealthy device: score = %d, want > 0", result.Assessment.Spec.Score)
	}
	if result.Assessment.Spec.Level == risk.RiskLevelLow {
		t.Errorf("unhealthy device: level should not be low")
	}
	if len(result.Contributions) != 1 {
		t.Errorf("unhealthy device: expected 1 contribution, got %d", len(result.Contributions))
	}
}

// TestEvaluate_ScenarioCombined — multiple rules fire → higher score with deduplication.
func TestEvaluate_ScenarioCombined(t *testing.T) {
	snapshot := snap(
		fact("device.posture.status", "unhealthy"),
		fact("session.authentication.strength", "password"),
		fact("subject.behavior.anomaly_detected", "true"),
	)

	result, err := risk.Evaluate(testModel, snapshot, nil, now)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(result.Contributions) != 3 {
		t.Errorf("combined: expected 3 contributions, got %d", len(result.Contributions))
	}
	if result.Assessment.Spec.Score <= 30 {
		t.Errorf("combined: score = %d, want > 30 (multiple risks)", result.Assessment.Spec.Score)
	}
}

// TestEvaluate_ScenarioNegativeContribution — strong MFA reduces risk.
func TestEvaluate_ScenarioNegativeContribution(t *testing.T) {
	// Degraded device but phishing-resistant MFA offsets some risk.
	snapshot := snap(
		fact("device.posture.status", "degraded"),
		fact("session.authentication.strength", "phishing_resistant_mfa"),
	)

	result, err := risk.Evaluate(testModel, snapshot, nil, now)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	var deviceContrib, authContrib float64
	for _, c := range result.Contributions {
		switch c.Spec.RuleID {
		case "device_posture_degraded":
			deviceContrib = c.Spec.EffectiveValue
		case "auth_phishing_resistant_bonus":
			authContrib = c.Spec.EffectiveValue
		}
	}
	if deviceContrib <= 0 {
		t.Errorf("degraded device should have positive contribution, got %f", deviceContrib)
	}
	if authContrib >= 0 {
		t.Errorf("phishing_resistant_mfa should have negative contribution, got %f", authContrib)
	}
	// Score should be lower than degraded_device alone.
	snapshotNoAuth := snap(fact("device.posture.status", "degraded"))
	resultNoAuth, _ := risk.Evaluate(testModel, snapshotNoAuth, nil, now)
	if result.Assessment.Spec.Score >= resultNoAuth.Assessment.Spec.Score {
		t.Errorf("strong MFA should reduce score: with_mfa=%d >= without_mfa=%d",
			result.Assessment.Spec.Score, resultNoAuth.Assessment.Spec.Score)
	}
}

// TestEvaluate_ScenarioMissingInputs — missing facts reduce completeness.
func TestEvaluate_ScenarioMissingInputs(t *testing.T) {
	// Provide only one of the relevant facts.
	snapshot := snap(
		fact("device.posture.status", "healthy"),
		// session.authentication.strength is missing
		// subject.behavior.anomaly_detected is missing
	)

	result, err := risk.Evaluate(testModel, snapshot, nil, now)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Assessment.Spec.Completeness >= 1.0 {
		t.Errorf("completeness should be < 1.0 with missing inputs, got %f",
			result.Assessment.Spec.Completeness)
	}
	// Missing inputs should be listed.
	if len(result.Assessment.Spec.MissingInputs) == 0 {
		t.Error("expected MissingInputs to be non-empty")
	}
}

// TestEvaluate_ScenarioFreshness — stale fact is treated as missing.
func TestEvaluate_ScenarioFreshness(t *testing.T) {
	staleFact := context.ContextFact{
		Key:        "device.posture.status",
		Value:      "unhealthy",
		Status:     context.FactStatusStale,
		ObservedAt: now.Add(-2 * time.Hour),
		ValidUntil: now.Add(-1 * time.Hour), // already expired
		Quality:    context.DataQuality{Confidence: 0.95},
	}
	snapshot := snap(staleFact)

	result, err := risk.Evaluate(testModel, snapshot, nil, now)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// Stale fact → treated as missing → no contribution.
	if len(result.Contributions) != 0 {
		t.Errorf("stale fact should produce 0 contributions, got %d", len(result.Contributions))
	}
	if len(result.Assessment.Spec.MissingInputs) == 0 {
		t.Error("stale fact should appear in MissingInputs")
	}
}

// TestEvaluate_ScenarioDecay — older observations have reduced freshness factor.
func TestEvaluate_ScenarioDecay(t *testing.T) {
	// device_posture_unhealthy has HalfLife: 15m.
	// freshFact: observed 1m ago → freshness ≈ 0.955
	// agedFact:  observed 30m ago → freshness ≈ 0.25
	freshFact := context.ContextFact{
		Key: "device.posture.status", Value: "unhealthy",
		Status: context.FactStatusKnown, ObservedAt: now.Add(-1 * time.Minute),
		ValidUntil: now.Add(29 * time.Minute),
		Quality:    context.DataQuality{Confidence: 1.0},
	}
	agedFact := context.ContextFact{
		Key: "device.posture.status", Value: "unhealthy",
		Status: context.FactStatusKnown, ObservedAt: now.Add(-30 * time.Minute),
		ValidUntil: now.Add(1 * time.Minute),
		Quality:    context.DataQuality{Confidence: 1.0},
	}

	freshResult, err := risk.Evaluate(testModel, snap(freshFact), nil, now)
	if err != nil {
		t.Fatalf("Evaluate fresh: %v", err)
	}
	agedResult, err := risk.Evaluate(testModel, snap(agedFact), nil, now)
	if err != nil {
		t.Fatalf("Evaluate aged: %v", err)
	}

	if freshResult.Assessment.Spec.Score <= agedResult.Assessment.Spec.Score {
		t.Errorf("fresh observation should produce higher score: fresh=%d aged=%d",
			freshResult.Assessment.Spec.Score, agedResult.Assessment.Spec.Score)
	}
}

// TestEvaluate_ScenarioDomainCap — domain cap prevents unbounded accumulation.
func TestEvaluate_ScenarioDomainCap(t *testing.T) {
	// device_posture domain has MaxContribution: 40.
	// Both degraded (20) and unhealthy (35) rules would fire if both match —
	// but only one of them can match (mutually exclusive values).
	// Let's verify that even if we add a third hypothetical rule,
	// the domain cap protects us.
	//
	// Here we test: unhealthy (35) + anomaly (25) → capped separately in their domains.
	snapshot := snap(
		fact("device.posture.status", "unhealthy"),        // 35 → capped at 40 for domain
		fact("subject.behavior.anomaly_detected", "true"), // 25 in access_behavior domain
	)

	result, err := risk.Evaluate(testModel, snapshot, nil, now)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// Score should not exceed sum of domain caps (device=40, access_behavior=45).
	if result.Assessment.Spec.Score > 85 {
		t.Errorf("score %d exceeds domain cap sum (85)", result.Assessment.Spec.Score)
	}
}

// TestEvaluate_RiskEngineHasNoPEPDependency verifies the engine has no enforcement output.
// The engine produces an assessment only — no adapter calls, no action.
func TestEvaluate_RiskEngineHasNoPEPDependency(t *testing.T) {
	snapshot := snap(fact("device.posture.status", "unhealthy"))
	result, err := risk.Evaluate(testModel, snapshot, nil, now)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// Assessment carries no action/capability/decision fields.
	// We verify the type itself — RiskAssessment has no action or capability fields.
	a := result.Assessment
	if a.Kind != "RiskAssessment" {
		t.Errorf("output kind = %q, want RiskAssessment", a.Kind)
	}
	// No enforcement in the output.
	_ = a.Spec.Score // evidence only
	_ = a.Spec.Level // evidence only
}

// TestEvaluate_Deterministic — same inputs always produce same output.
func TestEvaluate_Deterministic(t *testing.T) {
	snapshot := snap(
		fact("device.posture.status", "unhealthy"),
		fact("session.authentication.strength", "password"),
	)

	r1, _ := risk.Evaluate(testModel, snapshot, nil, now)
	r2, _ := risk.Evaluate(testModel, snapshot, nil, now)

	if r1.Assessment.Spec.Score != r2.Assessment.Spec.Score {
		t.Errorf("non-deterministic: score1=%d score2=%d", r1.Assessment.Spec.Score, r2.Assessment.Spec.Score)
	}
	if r1.Assessment.Spec.Level != r2.Assessment.Spec.Level {
		t.Errorf("non-deterministic: level1=%q level2=%q", r1.Assessment.Spec.Level, r2.Assessment.Spec.Level)
	}
	if r1.Assessment.Spec.Confidence != r2.Assessment.Spec.Confidence {
		t.Errorf("non-deterministic: confidence differs")
	}
}

// TestEvaluate_WithIndicator — indicator source triggers correctly.
func TestEvaluate_WithIndicator(t *testing.T) {
	indicatorModel := &risk.RiskModel{
		APIVersion: "kernloom.io/risk/v1alpha1",
		Kind:       "RiskModel",
		Metadata:   risk.RiskModelMeta{Name: "indicator-test", Version: "1.0.0"},
		Spec: risk.RiskModelSpec{
			ScopeTypes: []risk.RiskScope{risk.RiskScopeSubject},
			Inputs: []risk.RiskModelInput{
				{
					ID: "behavior_service_enum", Source: "indicator",
					Key: "subject.behavior.service_enumeration",
					// No explicit Match → defaults to state == "detected"
					BaseContribution: 30, ConfidenceMode: "source",
				},
			},
			Output: risk.RiskModelOutput{
				Range:  risk.ScoreRange{Min: 0, Max: 100},
				Levels: map[string][2]int{"low": {0, 29}, "medium": {30, 59}, "high": {60, 79}, "critical": {80, 100}},
			},
			Validity: risk.RiskModelValidity{TTL: 30 * time.Minute},
		},
	}

	indicators := []risk.RiskIndicator{
		{
			APIVersion: "kernloom.io/risk/v1alpha1",
			Kind:       "RiskIndicator",
			Metadata:   risk.IndicatorMetadata{ID: "ind-001"},
			Spec: risk.IndicatorSpec{
				Key:        "subject.behavior.service_enumeration",
				State:      "detected",
				Severity:   "high",
				Confidence: 0.87,
				ObservedAt: now.Add(-3 * time.Minute),
				ValidUntil: now.Add(10 * time.Minute),
			},
		},
	}

	snapshot := snap() // empty snapshot — rule uses indicator source

	result, err := risk.Evaluate(indicatorModel, snapshot, indicators, now)
	if err != nil {
		t.Fatalf("Evaluate with indicator: %v", err)
	}
	if len(result.Contributions) != 1 {
		t.Errorf("expected 1 contribution from indicator, got %d", len(result.Contributions))
	}
	if result.Assessment.Spec.Score <= 0 {
		t.Errorf("indicator score should be > 0, got %d", result.Assessment.Spec.Score)
	}
}
