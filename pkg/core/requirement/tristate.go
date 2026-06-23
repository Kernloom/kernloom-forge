// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package requirement

import (
	"fmt"
	"strconv"
	"strings"
)

type TruthValue string

const (
	TruthTrue    TruthValue = "true"
	TruthFalse   TruthValue = "false"
	TruthUnknown TruthValue = "unknown"
)

func EvaluateCondition(condition RequirementCondition, facts map[string]any) TruthValue {
	if strings.TrimSpace(condition.Signal) == "" {
		return TruthUnknown
	}
	actual, ok := facts[condition.Signal]
	if !ok || actual == nil {
		return TruthUnknown
	}
	switch strings.ReplaceAll(strings.ToLower(strings.TrimSpace(condition.Operator)), "-", "_") {
	case "eq", "==":
		return truthFromBool(valueEquals(actual, condition.Value))
	case "neq", "!=":
		return truthFromBool(!valueEquals(actual, condition.Value))
	case "in":
		return truthFromBool(valueIn(actual, condition.Value))
	case "not_in":
		return truthFromBool(!valueIn(actual, condition.Value))
	case "contains":
		ok, comparable := valueContains(actual, condition.Value)
		if !comparable {
			return TruthUnknown
		}
		return truthFromBool(ok)
	case "not_contains":
		ok, comparable := valueContains(actual, condition.Value)
		if !comparable {
			return TruthUnknown
		}
		return truthFromBool(!ok)
	case "gt", ">":
		return compareNumeric(actual, condition.Value, func(a, b float64) bool { return a > b })
	case "gte", ">=":
		return compareNumeric(actual, condition.Value, func(a, b float64) bool { return a >= b })
	case "lt", "<":
		return compareNumeric(actual, condition.Value, func(a, b float64) bool { return a < b })
	case "lte", "<=":
		return compareNumeric(actual, condition.Value, func(a, b float64) bool { return a <= b })
	default:
		return TruthUnknown
	}
}

func MissingContextBehavior(condition RequirementCondition) string {
	if condition.MissingContext != "" {
		return condition.MissingContext
	}
	return MissingContextDeny
}

func truthFromBool(value bool) TruthValue {
	if value {
		return TruthTrue
	}
	return TruthFalse
}

func valueEquals(actual, expected any) bool {
	return fmt.Sprint(actual) == fmt.Sprint(expected)
}

func valueIn(actual, expected any) bool {
	actualString := fmt.Sprint(actual)
	for _, item := range anyStringSlice(expected) {
		if item == actualString {
			return true
		}
	}
	return false
}

func valueContains(actual, expected any) (bool, bool) {
	if actual == nil || expected == nil {
		return false, false
	}
	actualString := fmt.Sprint(actual)
	expectedValues := anyStringSlice(expected)
	if len(expectedValues) == 0 {
		return false, false
	}
	switch typed := actual.(type) {
	case []string, []any:
		actualValues := anyStringSlice(typed)
		for _, want := range expectedValues {
			for _, got := range actualValues {
				if got == want {
					return true, true
				}
			}
		}
		return false, true
	default:
		for _, want := range expectedValues {
			if strings.Contains(actualString, want) {
				return true, true
			}
		}
		return false, true
	}
}

func compareNumeric(actual, expected any, cmp func(float64, float64) bool) TruthValue {
	left, ok := numberFromAny(actual)
	if !ok {
		return TruthUnknown
	}
	right, ok := numberFromAny(expected)
	if !ok {
		return TruthUnknown
	}
	return truthFromBool(cmp(left, right))
}

func numberFromAny(value any) (float64, bool) {
	switch typed := value.(type) {
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed, err == nil
	default:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(fmt.Sprint(value)), 64)
		return parsed, err == nil
	}
}

func anyStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{typed}
	default:
		if value == nil {
			return nil
		}
		return []string{fmt.Sprint(value)}
	}
}
