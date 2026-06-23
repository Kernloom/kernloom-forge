// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom-forge/internal/api"
)

func TestSelectAssignmentMatchesCapabilitiesAndAdapters(t *testing.T) {
	manifest := &assignmentManifest{
		Spec: assignmentSpec{Assignments: []nodePolicyAssignment{{
			ID:     "klshield-golden",
			Intent: "../policies/protect-ziti-controller-policy-intent.yaml",
			Target: "klshield-local",
			NodeSelector: nodeSelector{
				Adapters:     []string{"klshield"},
				Capabilities: []string{"enforce.traffic.rate_limit"},
			},
			RequiredCapabilities: []string{"enforce.access.deny"},
		}}},
	}
	node := testNodeRecord(t, []string{"enforce.traffic.rate_limit", "enforce.access.deny"}, []string{"klshield"})
	assignment, err := selectAssignment(manifest, node)
	if err != nil {
		t.Fatalf("selectAssignment: %v", err)
	}
	if assignment.ID != "klshield-golden" {
		t.Fatalf("assignment = %q", assignment.ID)
	}
}

func TestSelectAssignmentRejectsMissingCapabilities(t *testing.T) {
	manifest := &assignmentManifest{
		Spec: assignmentSpec{Assignments: []nodePolicyAssignment{{
			ID:     "klshield-golden",
			Intent: "../policies/protect-ziti-controller-policy-intent.yaml",
			Target: "klshield-local",
			NodeSelector: nodeSelector{
				Adapters: []string{"klshield"},
			},
			RequiredCapabilities: []string{"enforce.access.deny"},
		}}},
	}
	node := testNodeRecord(t, []string{"enforce.traffic.rate_limit"}, []string{"klshield"})
	_, err := selectAssignment(manifest, node)
	if err == nil || !strings.Contains(err.Error(), "capabilities are missing") {
		t.Fatalf("expected missing capability error, got %v", err)
	}
}

func TestSelectAssignmentMatchesLabels(t *testing.T) {
	manifest := &assignmentManifest{
		Spec: assignmentSpec{Assignments: []nodePolicyAssignment{
			{
				ID:     "staging-edge",
				Intent: "../policies/staging.intent",
				Target: "klshield-local",
				NodeSelector: nodeSelector{
					Adapters: []string{"klshield"},
					Labels: map[string]string{
						"env":  "staging",
						"role": "edge-gateway",
					},
				},
			},
			{
				ID:     "production-edge",
				Intent: "../policies/production.intent",
				Target: "klshield-local",
				NodeSelector: nodeSelector{
					Adapters: []string{"klshield"},
					Labels: map[string]string{
						"env":  "production",
						"role": "edge-gateway",
					},
				},
			},
		}},
	}
	node := testNodeRecordWithLabels(t,
		[]string{"enforce.traffic.rate_limit"},
		[]string{"klshield"},
		map[string]string{"env": "production", "role": "edge-gateway"},
	)
	assignment, err := selectAssignment(manifest, node)
	if err != nil {
		t.Fatalf("selectAssignment: %v", err)
	}
	if assignment.ID != "production-edge" {
		t.Fatalf("assignment = %q", assignment.ID)
	}
}

func TestSelectAssignmentRejectsLabelMismatch(t *testing.T) {
	manifest := &assignmentManifest{
		Spec: assignmentSpec{Assignments: []nodePolicyAssignment{{
			ID:     "payment-edge",
			Intent: "../policies/payment.intent",
			Target: "klshield-local",
			NodeSelector: nodeSelector{
				Adapters: []string{"klshield"},
				Labels: map[string]string{
					"service": "payment-api",
				},
			},
		}}},
	}
	node := testNodeRecordWithLabels(t,
		[]string{"enforce.traffic.rate_limit"},
		[]string{"klshield"},
		map[string]string{"service": "public-edge"},
	)
	_, err := selectAssignment(manifest, node)
	if !errors.Is(err, errNoPolicyAssignment) {
		t.Fatalf("expected no assignment, got %v", err)
	}
}

func TestSelectAssignmentNoMatch(t *testing.T) {
	manifest := &assignmentManifest{
		Spec: assignmentSpec{Assignments: []nodePolicyAssignment{{
			ID:     "klshield-golden",
			Intent: "../policies/protect-ziti-controller-policy-intent.yaml",
			Target: "klshield-local",
			NodeSelector: nodeSelector{
				Adapters: []string{"klshield"},
			},
		}}},
	}
	node := testNodeRecord(t, []string{"enforce.traffic.rate_limit"}, []string{"netfilter"})
	_, err := selectAssignment(manifest, node)
	if !errors.Is(err, errNoPolicyAssignment) {
		t.Fatalf("expected no assignment, got %v", err)
	}
}

func testNodeRecord(t *testing.T, caps []string, adapters []string) api.NodeRecord {
	t.Helper()
	return testNodeRecordWithLabels(t, caps, adapters, nil)
}

func testNodeRecordWithLabels(t *testing.T, caps []string, adapters []string, labels map[string]string) api.NodeRecord {
	t.Helper()
	effective := make([]contracts.ComponentCapabilityStatus, 0, len(caps))
	for _, capID := range caps {
		effective = append(effective, contracts.ComponentCapabilityStatus{ID: capID, Status: "available"})
	}
	adapterReports := make([]contracts.AdapterSummary, 0, len(adapters))
	for _, adapterID := range adapters {
		adapterReports = append(adapterReports, contracts.AdapterSummary{ID: adapterID, Enabled: true})
	}
	controlledByAdapter := "builtin-klshield"
	if len(adapters) > 0 {
		controlledByAdapter = adapters[0]
	}
	return api.NodeRecord{
		NodeID: "node-test",
		Inventory: contracts.ComponentInventory{
			Metadata: contracts.ComponentInventoryMetadata{ID: "node-test"},
			ControlledBy: contracts.ComponentInventoryControl{
				NodeID:        "node-test",
				PluginAdapter: controlledByAdapter,
			},
			EffectiveCapabilities: effective,
			Labels:                labels,
		},
		ConfigReport: contracts.KLIQConfigAssetReport{
			Adapters: adapterReports,
		},
		EnrolledAt: time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC),
		LastSeenAt: time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC),
	}
}
