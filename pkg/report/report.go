// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package report

import (
	"time"

	"github.com/kernloom/kernloom-forge/pkg/configpdp"
	"github.com/kernloom/kernloom-forge/pkg/core/plan"
)

type ReportSet struct {
	APIVersion string            `yaml:"apiVersion" json:"apiVersion"`
	Kind       string            `yaml:"kind" json:"kind"`
	Metadata   ReportSetMetadata `yaml:"metadata" json:"metadata"`
	Spec       ReportSetSpec     `yaml:"spec" json:"spec"`
}

type ReportSetMetadata struct {
	SourcePolicy string    `yaml:"sourcePolicy" json:"sourcePolicy"`
	GeneratedAt  time.Time `yaml:"generatedAt" json:"generatedAt"`
}

type ReportSetSpec struct {
	Coverage      []CoverageReport               `yaml:"coverage" json:"coverage"`
	Delegation    []DelegationReportEntry        `yaml:"delegation,omitempty" json:"delegation,omitempty"`
	Downgrades    []SemanticDowngradeReportEntry `yaml:"downgrades,omitempty" json:"downgrades,omitempty"`
	ConfigPDP     []configpdp.ValidationReport   `yaml:"configPDP,omitempty" json:"configPDP,omitempty"`
	TargetSummary []TargetIntegrationReportEntry `yaml:"targetSummary,omitempty" json:"targetSummary,omitempty"`
}

type CoverageReport struct {
	Target               string   `yaml:"target" json:"target"`
	Deployable           bool     `yaml:"deployable" json:"deployable"`
	RuntimeModel         string   `yaml:"runtimeModel" json:"runtimeModel"`
	SemanticFidelity     string   `yaml:"semanticFidelity" json:"semanticFidelity"`
	Implemented          []string `yaml:"implemented,omitempty" json:"implemented,omitempty"`
	Delegated            []string `yaml:"delegated,omitempty" json:"delegated,omitempty"`
	CompensatingControls []string `yaml:"compensatingControls,omitempty" json:"compensatingControls,omitempty"`
	Downgraded           []string `yaml:"downgraded,omitempty" json:"downgraded,omitempty"`
	Unsupported          []string `yaml:"unsupported,omitempty" json:"unsupported,omitempty"`
}

type DelegationReportEntry struct {
	Target      string `yaml:"target" json:"target"`
	Requirement string `yaml:"requirement" json:"requirement"`
	Owner       string `yaml:"owner" json:"owner"`
	Note        string `yaml:"note,omitempty" json:"note,omitempty"`
}

type SemanticDowngradeReportEntry struct {
	Target      string `yaml:"target" json:"target"`
	Requirement string `yaml:"requirement" json:"requirement"`
	From        string `yaml:"from" json:"from"`
	To          string `yaml:"to" json:"to"`
	Reason      string `yaml:"reason" json:"reason"`
}

type TargetIntegrationReportEntry struct {
	Target       string `yaml:"target" json:"target"`
	RuntimeModel string `yaml:"runtimeModel" json:"runtimeModel"`
	Deployable   bool   `yaml:"deployable" json:"deployable"`
}

func Build(sourcePolicy string, plans []*plan.EnforcementPlan, validations []configpdp.ValidationReport) ReportSet {
	rs := ReportSet{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "ReportSet",
		Metadata: ReportSetMetadata{
			SourcePolicy: sourcePolicy,
			GeneratedAt:  time.Now().UTC(),
		},
	}
	for _, p := range plans {
		if p == nil {
			continue
		}
		cov := CoverageReport{
			Target:               p.Metadata.Target,
			Deployable:           p.Spec.Summary.Deployable,
			RuntimeModel:         p.Spec.Summary.RuntimeModel,
			SemanticFidelity:     p.Spec.Summary.SemanticFidelity,
			Delegated:            append([]string(nil), p.Spec.Summary.Delegation...),
			CompensatingControls: append([]string(nil), p.Spec.Summary.CompensatingControls...),
			Downgraded:           append([]string(nil), p.Spec.Summary.Downgrades...),
			Unsupported:          append([]string(nil), p.Spec.Summary.Unsupported...),
		}
		for _, req := range p.Spec.Requirements {
			switch req.Status {
			case plan.StatusImplemented:
				cov.Implemented = append(cov.Implemented, req.ID)
			case plan.StatusDelegated:
				owner := ""
				note := ""
				if req.Delegation != nil {
					owner = req.Delegation.EvaluationOwner
					note = req.Delegation.Note
				}
				rs.Spec.Delegation = append(rs.Spec.Delegation, DelegationReportEntry{
					Target: p.Metadata.Target, Requirement: req.ID, Owner: owner, Note: note,
				})
			case plan.StatusPartial:
				if req.Downgrade != nil {
					rs.Spec.Downgrades = append(rs.Spec.Downgrades, SemanticDowngradeReportEntry{
						Target: p.Metadata.Target, Requirement: req.ID,
						From: req.Downgrade.From, To: req.Downgrade.To, Reason: req.Downgrade.Reason,
					})
				}
			}
		}
		rs.Spec.Coverage = append(rs.Spec.Coverage, cov)
		rs.Spec.TargetSummary = append(rs.Spec.TargetSummary, TargetIntegrationReportEntry{
			Target: p.Metadata.Target, RuntimeModel: p.Spec.Summary.RuntimeModel, Deployable: p.Spec.Summary.Deployable,
		})
	}
	rs.Spec.ConfigPDP = validations
	return rs
}
