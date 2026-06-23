// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package report

import (
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
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
	Coverage        []CoverageReport               `yaml:"coverage" json:"coverage"`
	ContextCoverage []ContextCoverageReportEntry   `yaml:"contextCoverage,omitempty" json:"contextCoverage,omitempty"`
	MissingSignals  []MissingSignalReportEntry     `yaml:"missingSignals,omitempty" json:"missingSignals,omitempty"`
	Delegation      []DelegationReportEntry        `yaml:"delegation,omitempty" json:"delegation,omitempty"`
	Downgrades      []SemanticDowngradeReportEntry `yaml:"downgrades,omitempty" json:"downgrades,omitempty"`
	RuntimeNotes    []RuntimeNoteReportEntry       `yaml:"runtimeNotes,omitempty" json:"runtimeNotes,omitempty"`
	GapMetadata     []contracts.RuntimeGapMetadata `yaml:"gapMetadata,omitempty" json:"gapMetadata,omitempty"`
	ConfigPDP       []configpdp.ValidationReport   `yaml:"configPDP,omitempty" json:"configPDP,omitempty"`
	TargetSummary   []TargetIntegrationReportEntry `yaml:"targetSummary,omitempty" json:"targetSummary,omitempty"`
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

type RuntimeNoteReportEntry struct {
	Target      string   `yaml:"target" json:"target"`
	Requirement string   `yaml:"requirement" json:"requirement"`
	Notes       []string `yaml:"notes" json:"notes"`
}

type TargetIntegrationReportEntry struct {
	Target       string `yaml:"target" json:"target"`
	RuntimeModel string `yaml:"runtimeModel" json:"runtimeModel"`
	Deployable   bool   `yaml:"deployable" json:"deployable"`
}

type ContextCoverageReportEntry struct {
	Target      string   `yaml:"target" json:"target"`
	Requirement string   `yaml:"requirement" json:"requirement"`
	ContextKey  string   `yaml:"contextKey" json:"contextKey"`
	Status      string   `yaml:"status" json:"status"`
	Owner       string   `yaml:"owner,omitempty" json:"owner,omitempty"`
	Notes       []string `yaml:"notes,omitempty" json:"notes,omitempty"`
}

type MissingSignalReportEntry struct {
	Target      string `yaml:"target" json:"target"`
	Requirement string `yaml:"requirement" json:"requirement"`
	ContextKey  string `yaml:"contextKey" json:"contextKey"`
	Status      string `yaml:"status" json:"status"`
	Reason      string `yaml:"reason" json:"reason"`
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
			if gap := gapMetadataFromRequirement(p, req); gap.ID != "" {
				rs.Spec.GapMetadata = append(rs.Spec.GapMetadata, gap)
			}
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
			if len(req.RuntimeNotes) > 0 {
				rs.Spec.RuntimeNotes = append(rs.Spec.RuntimeNotes, RuntimeNoteReportEntry{
					Target:      p.Metadata.Target,
					Requirement: req.ID,
					Notes:       append([]string(nil), req.RuntimeNotes...),
				})
			}
			if key := contextKeyFromRequirement(req); key != "" {
				owner := ""
				if req.Ownership != nil {
					owner = req.Ownership.RiskAssessmentOwner
					if owner == "" {
						owner = req.Ownership.PolicyEvaluationOwner
					}
				}
				rs.Spec.ContextCoverage = append(rs.Spec.ContextCoverage, ContextCoverageReportEntry{
					Target:      p.Metadata.Target,
					Requirement: req.ID,
					ContextKey:  key,
					Status:      string(req.Status),
					Owner:       owner,
					Notes:       append([]string(nil), req.RuntimeNotes...),
				})
				if req.Status == plan.StatusUnsupported || req.Status == plan.StatusPartial {
					rs.Spec.MissingSignals = append(rs.Spec.MissingSignals, MissingSignalReportEntry{
						Target:      p.Metadata.Target,
						Requirement: req.ID,
						ContextKey:  key,
						Status:      string(req.Status),
						Reason:      "context signal is missing, stale, unsupported or downgraded for this target",
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

func gapMetadataFromRequirement(p *plan.EnforcementPlan, req plan.RequirementEnforcement) contracts.RuntimeGapMetadata {
	gapType, behavior, severity := reportGapClassification(req.Status)
	if gapType == "" {
		return contracts.RuntimeGapMetadata{}
	}
	meta := map[string]string{}
	if req.Capability != "" {
		meta["capability"] = req.Capability
	}
	if req.Fidelity != "" {
		meta["fidelity"] = req.Fidelity
	}
	if req.Downgrade != nil {
		meta["from"] = req.Downgrade.From
		meta["to"] = req.Downgrade.To
	}
	return contracts.RuntimeGapMetadata{
		ID:          "gap-" + strings.ReplaceAll(req.ID, ".", "-"),
		Type:        gapType,
		Behavior:    behavior,
		Target:      p.Metadata.Target,
		Requirement: req.ID,
		Severity:    severity,
		Deployable:  p.Spec.Summary.Deployable,
		Reason:      reportGapReason(req),
		Meta:        meta,
	}
}

func reportGapClassification(status plan.RequirementStatus) (gapType, behavior, severity string) {
	switch status {
	case plan.StatusUnsupported:
		return "enforcement_gap", "fail_closed", "high"
	case plan.StatusPartial:
		return "semantic_downgrade", "require_review", "medium"
	case plan.StatusDelegated:
		return "delegation_gap", "report", "low"
	case plan.StatusCompensatingControl:
		return "compensating_control", "report", "low"
	default:
		return "", "", ""
	}
}

func reportGapReason(req plan.RequirementEnforcement) string {
	if req.Downgrade != nil && req.Downgrade.Reason != "" {
		return req.Downgrade.Reason
	}
	if len(req.RuntimeNotes) > 0 {
		return strings.Join(req.RuntimeNotes, " ")
	}
	switch req.Status {
	case plan.StatusUnsupported:
		return "requirement cannot be satisfied by this target"
	case plan.StatusPartial:
		return "requirement is implemented with reduced semantic fidelity"
	case plan.StatusDelegated:
		return "requirement evaluation is delegated to target PDP"
	case plan.StatusCompensatingControl:
		return "requirement is enforced through a compensating runtime action"
	default:
		return ""
	}
}

func contextKeyFromRequirement(req plan.RequirementEnforcement) string {
	switch req.RequirementKind {
	case "auth_strength", "risk_level", "device_posture", "session_context", "subject_identity", "resource_identity":
	default:
		return ""
	}
	for _, token := range strings.Fields(req.Requirement) {
		token = strings.Trim(token, "()!'\"")
		if strings.Contains(token, ".") {
			return token
		}
	}
	return ""
}
