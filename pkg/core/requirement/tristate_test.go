// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package requirement

import "testing"

func TestEvaluateConditionTriState(t *testing.T) {
	condition := RequirementCondition{
		Signal:   "subject.risk.level",
		Operator: "eq",
		Value:    "low",
	}
	if got := EvaluateCondition(condition, map[string]any{"subject.risk.level": "low"}); got != TruthTrue {
		t.Fatalf("matching condition = %s, want true", got)
	}
	if got := EvaluateCondition(condition, map[string]any{"subject.risk.level": "high"}); got != TruthFalse {
		t.Fatalf("non-matching condition = %s, want false", got)
	}
	if got := EvaluateCondition(condition, map[string]any{}); got != TruthUnknown {
		t.Fatalf("missing context = %s, want unknown", got)
	}
}

func TestEvaluateConditionMissingNotInIsUnknown(t *testing.T) {
	condition := RequirementCondition{
		Signal:         "subject.groups",
		Operator:       "not_in",
		Value:          []string{"kernloom-admins"},
		MissingContext: MissingContextDeny,
	}
	if got := EvaluateCondition(condition, map[string]any{}); got != TruthUnknown {
		t.Fatalf("missing not_in context = %s, want unknown", got)
	}
	if got := MissingContextBehavior(condition); got != MissingContextDeny {
		t.Fatalf("missing context behavior = %q", got)
	}
}

func TestEvaluateConditionNumericAndContains(t *testing.T) {
	score := RequirementCondition{
		Signal:   "subject.risk.score",
		Operator: "gte",
		Value:    60,
	}
	if got := EvaluateCondition(score, map[string]any{"subject.risk.score": "73"}); got != TruthTrue {
		t.Fatalf("numeric comparison = %s, want true", got)
	}
	if got := EvaluateCondition(score, map[string]any{"subject.risk.score": "spicy"}); got != TruthUnknown {
		t.Fatalf("non-numeric comparison = %s, want unknown", got)
	}

	groups := RequirementCondition{
		Signal:   "subject.groups",
		Operator: "contains",
		Value:    "kernloom-admins",
	}
	if got := EvaluateCondition(groups, map[string]any{"subject.groups": []string{"developers", "kernloom-admins"}}); got != TruthTrue {
		t.Fatalf("contains comparison = %s, want true", got)
	}
	if got := EvaluateCondition(groups, map[string]any{}); got != TruthUnknown {
		t.Fatalf("missing contains comparison = %s, want unknown", got)
	}
}
