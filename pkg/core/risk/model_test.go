// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package risk_test

import (
	"testing"

	"github.com/kernloom/kernloom-forge/pkg/core/risk"
)

const validModelYAML = `
apiVersion: kernloom.io/risk/v1alpha1
kind: RiskModel
metadata:
  name: test-risk-model
  version: "1.0.0"
  owner: security-architecture
spec:
  scopeTypes: [subject, device]
  inputs:
    - id: device_posture_unhealthy
      source: context
      key: device.posture.status
      match: unhealthy
      baseContribution: 35
      confidenceMode: source
    - id: strong_mfa_bonus
      source: context
      key: session.authentication.strength
      match: phishing_resistant_mfa
      baseContribution: -10
  output:
    range:
      min: 0
      max: 100
    levels:
      low:      [0, 29]
      medium:   [30, 59]
      high:     [60, 79]
      critical: [80, 100]
  validity:
    ttl: 30m
    minConfidence: 0.60
`

func TestParseModel_Valid(t *testing.T) {
	m, err := risk.ParseModel([]byte(validModelYAML))
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}
	if m.Metadata.Name != "test-risk-model" {
		t.Errorf("name = %q, want test-risk-model", m.Metadata.Name)
	}
	if len(m.Spec.Inputs) != 2 {
		t.Errorf("inputs count = %d, want 2", len(m.Spec.Inputs))
	}
}

func TestParseModel_VendorKeyRejected(t *testing.T) {
	// A risk model must not use vendor-namespaced keys in its rules.
	vendorKeyYAML := `
apiVersion: kernloom.io/risk/v1alpha1
kind: RiskModel
metadata:
  name: bad-model
  version: "1.0.0"
spec:
  scopeTypes: [subject]
  inputs:
    - id: bad_rule
      source: context
      key: openziti.posture_result
      match: fail
      baseContribution: 40
  output:
    range: {min: 0, max: 100}
    levels:
      low: [0, 29]
  validity:
    ttl: 30m
`
	_, err := risk.ParseModel([]byte(vendorKeyYAML))
	if err == nil {
		t.Error("model with vendor-namespaced key should be rejected")
	}
}

func TestParseModel_ZitiKeyRejected(t *testing.T) {
	zitiKeyYAML := `
apiVersion: kernloom.io/risk/v1alpha1
kind: RiskModel
metadata:
  name: bad-ziti-model
  version: "1.0.0"
spec:
  scopeTypes: [subject]
  inputs:
    - id: bad_rule
      source: indicator
      key: ziti.service_access_denied
      baseContribution: 20
  output:
    range: {min: 0, max: 100}
    levels:
      low: [0, 29]
  validity:
    ttl: 30m
`
	_, err := risk.ParseModel([]byte(zitiKeyYAML))
	if err == nil {
		t.Error("model with ziti.* key should be rejected")
	}
}

func TestParseModel_MissingVersion(t *testing.T) {
	noVersionYAML := `
apiVersion: kernloom.io/risk/v1alpha1
kind: RiskModel
metadata:
  name: no-version
spec:
  scopeTypes: [subject]
  inputs: []
  output:
    range: {min: 0, max: 100}
    levels:
      low: [0, 29]
  validity:
    ttl: 30m
`
	_, err := risk.ParseModel([]byte(noVersionYAML))
	if err == nil {
		t.Error("model without version should be rejected")
	}
}

func TestLevelFromScore(t *testing.T) {
	tests := []struct {
		score int
		want  risk.RiskLevel
	}{
		{0, risk.RiskLevelLow},
		{15, risk.RiskLevelLow},
		{29, risk.RiskLevelLow},
		{30, risk.RiskLevelMedium},
		{59, risk.RiskLevelMedium},
		{60, risk.RiskLevelHigh},
		{79, risk.RiskLevelHigh},
		{80, risk.RiskLevelCritical},
		{100, risk.RiskLevelCritical},
		{-1, risk.RiskLevelUnknown},
	}
	for _, tt := range tests {
		got := risk.LevelFromScore(tt.score)
		if got != tt.want {
			t.Errorf("LevelFromScore(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}
