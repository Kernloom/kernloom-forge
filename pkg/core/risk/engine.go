// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package risk

import (
	"crypto/rand"
	"fmt"
	"math"
	"time"

	"github.com/kernloom/kernloom-forge/pkg/core/context"
)

// EvaluateOptions controls optional evaluation behaviour.
type EvaluateOptions struct {
	// SnapshotAge is the age of the context snapshot relative to now.
	// Used to degrade confidence when a snapshot is old.
	// Zero means use now — snapshot.SnapshotAt for age.
	SnapshotAge time.Duration
}

// EvalResult contains the full output of Evaluate including intermediate
// contributions (useful for explainability and debugging).
type EvalResult struct {
	Assessment    *RiskAssessment
	Contributions []RiskContribution
}

// Evaluate runs the deterministic risk model against a context snapshot and
// a set of pre-computed risk indicators.
//
// The function is pure: no network, no disk, no side effects.
// Identical inputs always produce identical output — suitable for
// Forge simulation, CI validation, KLIQ local_lite/local_full modes,
// and Correlate global aggregation.
//
// now is the reference time for decay and freshness calculations.
// Pass a fixed time in tests to get reproducible results.
func Evaluate(
	model *RiskModel,
	snapshot *context.ContextSnapshot,
	indicators []RiskIndicator,
	now time.Time,
) (*EvalResult, error) {
	if model == nil {
		return nil, fmt.Errorf("risk engine: model must not be nil")
	}
	if snapshot == nil {
		return nil, fmt.Errorf("risk engine: context snapshot must not be nil")
	}
	if err := model.Validate(); err != nil {
		return nil, fmt.Errorf("risk engine: invalid model: %w", err)
	}

	indicatorIndex := buildIndicatorIndex(indicators)

	// Domain accumulators: map[domain] → accumulated effective value
	domainScores := make(map[string]float64)
	var contributions []RiskContribution
	var missingInputs []string
	availableCount := 0
	totalCount := len(model.Spec.Inputs)

	totalConfidenceWeight := 0.0
	totalConfidenceValue := 0.0

	for _, inp := range model.Spec.Inputs {
		result := evaluateInput(inp, snapshot, indicatorIndex, now)

		if result.missing {
			missingInputs = append(missingInputs, inp.Key)
			continue
		}
		availableCount++

		if !result.matched {
			// Fact is available but the condition did not fire — still complete.
			continue
		}

		// Compute effective value = base × confidence_factor × freshness_factor.
		effectiveValue := float64(inp.BaseContribution) * result.confidenceFactor * result.freshnessFactor

		domain := inp.Domain
		if domain == "" {
			domain = "default"
		}
		domainScores[domain] += effectiveValue

		// Track confidence for the overall assessment (weighted by |effective|).
		weight := math.Abs(effectiveValue)
		totalConfidenceWeight += weight
		totalConfidenceValue += weight * result.confidenceFactor

		contributions = append(contributions, RiskContribution{
			APIVersion: "kernloom.io/risk/v1alpha1",
			Kind:       "RiskContribution",
			Spec: ContributionSpec{
				ModelRef:         ModelRef{ID: model.Metadata.Name, Version: model.Metadata.Version},
				RuleID:           inp.ID,
				ContextKey:       inp.Key,
				BaseValue:        inp.BaseContribution,
				Direction:        direction(inp.BaseContribution),
				ConfidenceFactor: result.confidenceFactor,
				FreshnessFactor:  result.freshnessFactor,
				EffectiveValue:   effectiveValue,
			},
		})
	}

	// Apply per-domain caps and sum.
	rawScore := 0.0
	domainResult := make(map[string]DomainScore)

	for domain, accumulated := range domainScores {
		cappedValue := accumulated
		if cfg, hasCap := model.Spec.Domains[domain]; hasCap && cfg.MaxContribution > 0 {
			if accumulated > float64(cfg.MaxContribution) {
				cappedValue = float64(cfg.MaxContribution)
			}
		}
		rawScore += cappedValue

		// Domain confidence = simple average of contributing confidences in this domain.
		// (Simplified: use the global confidence factor for now.)
		domainResult[domain] = DomainScore{
			Score:      clampInt(int(math.Round(cappedValue)), 0, model.Spec.Output.Range.Max),
			Confidence: safeDivide(totalConfidenceValue, totalConfidenceWeight),
		}
	}

	// Clamp total score to model output range.
	minScore := model.Spec.Output.Range.Min
	maxScore := model.Spec.Output.Range.Max
	if maxScore == 0 {
		maxScore = 100
	}
	finalScore := clampInt(int(math.Round(rawScore)), minScore, maxScore)

	// Assessment confidence: weighted average of all contributing confidences.
	assessmentConfidence := safeDivide(totalConfidenceValue, totalConfidenceWeight)

	// Completeness: fraction of model inputs that had available data.
	var completeness float64
	if totalCount > 0 {
		completeness = float64(availableCount) / float64(totalCount)
	}

	// Validity window from model.
	validUntil := now.Add(model.Spec.Validity.TTL)
	if model.Spec.Validity.TTL == 0 {
		validUntil = now.Add(30 * time.Minute)
	}

	// Build ContributionRefs for the assessment.
	var contributionRefs []ContributionRef
	for i, c := range contributions {
		contributionRefs = append(contributionRefs, ContributionRef{
			Ref:            fmt.Sprintf("contribution-%d-%s", i, c.Spec.RuleID),
			EffectiveValue: c.Spec.EffectiveValue,
		})
	}

	// Collect reason codes from contributions.
	var reasonCodes []string
	for _, c := range contributions {
		if c.Spec.EffectiveValue > 0 {
			reasonCodes = append(reasonCodes, fmt.Sprintf("RULE_%s", c.Spec.RuleID))
		}
	}

	assessment := &RiskAssessment{
		APIVersion: "kernloom.io/risk/v1alpha1",
		Kind:       "RiskAssessment",
		Metadata: AssessmentMetadata{
			ID: generateID(),
		},
		Spec: AssessmentSpec{
			Score:         finalScore,
			Level:         levelFromModelThresholds(finalScore, model),
			Confidence:    assessmentConfidence,
			Completeness:  completeness,
			Model:         ModelRef{ID: model.Metadata.Name, Version: model.Metadata.Version, Owner: model.Metadata.Owner},
			CalculatedAt:  now,
			ValidUntil:    validUntil,
			Domains:       domainResult,
			Contributors:  contributionRefs,
			MissingInputs: missingInputs,
			ReasonCodes:   reasonCodes,
		},
	}

	// Degrade confidence when snapshot is older.
	if !snapshot.SnapshotAt.IsZero() {
		age := now.Sub(snapshot.SnapshotAt)
		if age > 0 && model.Spec.Validity.TTL > 0 {
			ageFactor := 1.0 - math.Min(1.0, float64(age)/float64(model.Spec.Validity.TTL))
			assessment.Spec.Confidence *= ageFactor
		}
	}

	return &EvalResult{
		Assessment:    assessment,
		Contributions: contributions,
	}, nil
}

// inputEvalResult is the internal result of evaluating a single model input.
type inputEvalResult struct {
	missing          bool // fact/indicator was not found or was stale
	matched          bool // condition fired
	confidenceFactor float64
	freshnessFactor  float64
}

// evaluateInput checks whether a single model rule fires and computes factors.
func evaluateInput(
	inp RiskModelInput,
	snapshot *context.ContextSnapshot,
	indicatorIndex map[string]RiskIndicator,
	now time.Time,
) inputEvalResult {
	switch inp.Source {
	case "context":
		return evalContextInput(inp, snapshot, now)
	case "indicator":
		return evalIndicatorInput(inp, indicatorIndex, now)
	case "vendor_assessment":
		return evalVendorInput(inp, snapshot, now)
	default:
		// Unknown source type — treat as missing.
		return inputEvalResult{missing: true}
	}
}

// evalContextInput evaluates a rule against the ContextSnapshot.
func evalContextInput(inp RiskModelInput, snapshot *context.ContextSnapshot, now time.Time) inputEvalResult {
	fact := snapshot.FactByKey(inp.Key)
	if fact == nil {
		return inputEvalResult{missing: true}
	}
	if fact.Status == context.FactStatusMissing {
		return inputEvalResult{missing: true}
	}
	if fact.Status == context.FactStatusStale {
		return inputEvalResult{missing: true}
	}
	// Fact is available (even if conflicting or unknown — we still have a value).
	if !fact.ValidUntil.IsZero() && now.After(fact.ValidUntil) {
		return inputEvalResult{missing: true}
	}

	matched := matchesValue(fact.Value, inp.Match)

	confidenceFactor := 1.0
	if inp.ConfidenceMode == "source" {
		confidenceFactor = fact.Quality.Confidence
		if confidenceFactor <= 0 {
			confidenceFactor = 0.5 // safe default when confidence is not set
		}
	}

	freshnessFactor := computeFreshness(inp.Decay, fact.ObservedAt, now)

	return inputEvalResult{
		missing:          false,
		matched:          matched,
		confidenceFactor: confidenceFactor,
		freshnessFactor:  freshnessFactor,
	}
}

// evalIndicatorInput evaluates a rule against the indicator index.
func evalIndicatorInput(inp RiskModelInput, index map[string]RiskIndicator, now time.Time) inputEvalResult {
	ind, ok := index[inp.Key]
	if !ok {
		return inputEvalResult{missing: true}
	}
	if !ind.Spec.ValidUntil.IsZero() && now.After(ind.Spec.ValidUntil) {
		return inputEvalResult{missing: true}
	}

	// Indicators match when state is "detected" (or when Match overrides the state).
	matched := false
	if inp.Match != nil {
		matched = matchesValue(ind.Spec.State, inp.Match)
	} else {
		matched = ind.Spec.State == "detected"
	}

	freshnessFactor := computeFreshness(inp.Decay, ind.Spec.ObservedAt, now)

	return inputEvalResult{
		missing:          false,
		matched:          matched,
		confidenceFactor: ind.Spec.Confidence,
		freshnessFactor:  freshnessFactor,
	}
}

// evalVendorInput evaluates a rule against VendorAssessments in the snapshot.
// Vendor keys remain namespaced; the rule must reference the vendor key explicitly.
func evalVendorInput(inp RiskModelInput, snapshot *context.ContextSnapshot, now time.Time) inputEvalResult {
	for _, va := range snapshot.VendorAssessments {
		if va.Key != inp.Key {
			continue
		}
		if !va.Provenance.CollectedAt.IsZero() && inp.Decay.HalfLife > 0 {
			age := now.Sub(va.Provenance.CollectedAt)
			if age > inp.Decay.HalfLife*4 {
				return inputEvalResult{missing: true}
			}
		}
		matched := matchesValue(va.Value, inp.Match)
		freshnessFactor := computeFreshness(inp.Decay, va.Provenance.CollectedAt, now)
		return inputEvalResult{
			missing:          false,
			matched:          matched,
			confidenceFactor: 1.0, // vendor assessments don't have a confidence field
			freshnessFactor:  freshnessFactor,
		}
	}
	return inputEvalResult{missing: true}
}

// computeFreshness returns the freshness decay factor (0.0–1.0).
// Uses exponential decay: factor = 2^(−age/halfLife).
// Returns 1.0 when halfLife is 0 (no decay configured).
func computeFreshness(decay DecayConfig, observedAt time.Time, now time.Time) float64 {
	if decay.HalfLife <= 0 || observedAt.IsZero() {
		return 1.0
	}
	age := now.Sub(observedAt)
	if age <= 0 {
		return 1.0
	}
	exponent := -float64(age) / float64(decay.HalfLife)
	return math.Pow(2, exponent)
}

// matchesValue returns true when factValue satisfies the match condition.
// nil match means "any non-nil, non-empty value".
func matchesValue(factValue any, match any) bool {
	if match == nil {
		return factValue != nil && fmt.Sprintf("%v", factValue) != ""
	}
	return fmt.Sprintf("%v", factValue) == fmt.Sprintf("%v", match)
}

// levelFromModelThresholds derives a RiskLevel from the model's configured thresholds.
// Falls back to the default LevelFromScore when no thresholds are configured.
func levelFromModelThresholds(score int, model *RiskModel) RiskLevel {
	if len(model.Spec.Output.Levels) == 0 {
		return LevelFromScore(score)
	}
	// Check most severe levels first.
	for _, level := range []string{"critical", "high", "medium", "low"} {
		if bounds, ok := model.Spec.Output.Levels[level]; ok {
			if len(bounds) == 2 && score >= bounds[0] && score <= bounds[1] {
				return RiskLevel(level)
			}
		}
	}
	return RiskLevelUnknown
}

// buildIndicatorIndex creates a map from indicator key to indicator.
// When multiple indicators share the same key, the highest-confidence one wins.
func buildIndicatorIndex(indicators []RiskIndicator) map[string]RiskIndicator {
	index := make(map[string]RiskIndicator, len(indicators))
	for _, ind := range indicators {
		if existing, exists := index[ind.Spec.Key]; exists {
			if ind.Spec.Confidence > existing.Spec.Confidence {
				index[ind.Spec.Key] = ind
			}
		} else {
			index[ind.Spec.Key] = ind
		}
	}
	return index
}

// direction returns "increase" for positive values, "decrease" for negative.
func direction(value int) string {
	if value < 0 {
		return "decrease"
	}
	return "increase"
}

// clampInt clamps v to [min, max].
func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// safeDivide returns num/denom or 0 when denom is zero.
func safeDivide(num, denom float64) float64 {
	if denom == 0 {
		return 0
	}
	return num / denom
}

// generateID returns a random UUIDv4 string.
func generateID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
