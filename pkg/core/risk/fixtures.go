// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package risk

import "time"

// FixtureModel returns a deterministic P1 risk model for fixture snapshots.
func FixtureModel() *RiskModel {
	return &RiskModel{
		APIVersion: "kernloom.io/risk/v1alpha1",
		Kind:       "RiskModel",
		Metadata: RiskModelMeta{
			Name:    "fixture-enterprise-access-risk",
			Version: "1.0.0",
			Owner:   "security-architecture",
		},
		Spec: RiskModelSpec{
			ScopeTypes: []RiskScope{RiskScopeSubject, RiskScopeDevice, RiskScopeSession},
			Domains: map[string]DomainConfig{
				"device_posture":  {MaxContribution: 45},
				"access_behavior": {MaxContribution: 35},
				"authentication":  {MaxContribution: 20},
			},
			Inputs: []RiskModelInput{
				{
					ID: "device_posture_unhealthy", Source: "context",
					Key: "device.posture.status", Match: "unhealthy",
					Domain: "device_posture", BaseContribution: 45,
					ConfidenceMode: "source",
					Decay:          DecayConfig{HalfLife: 15 * time.Minute},
				},
				{
					ID: "subject_behavior_anomaly", Source: "context",
					Key: "subject.behavior.anomaly_detected", Match: true,
					Domain: "access_behavior", BaseContribution: 30,
					ConfidenceMode: "source",
					Decay:          DecayConfig{HalfLife: 10 * time.Minute},
				},
				{
					ID: "phishing_resistant_mfa_bonus", Source: "context",
					Key: "session.authentication.strength", Match: "phishing_resistant_mfa",
					Domain: "authentication", BaseContribution: -15,
					ConfidenceMode: "fixed",
				},
			},
			Output: RiskModelOutput{
				Range: ScoreRange{Min: 0, Max: 100},
				Levels: map[string][2]int{
					"low":      {0, 29},
					"medium":   {30, 59},
					"high":     {60, 79},
					"critical": {80, 100},
				},
			},
			Validity: RiskModelValidity{
				TTL:             30 * time.Minute,
				MinConfidence:   0.6,
				MinCompleteness: 0.6,
			},
		},
	}
}
