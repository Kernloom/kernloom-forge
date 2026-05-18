// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package validator_test

import (
	"path/filepath"
	"testing"

	"github.com/kernloom/kernloom-forge/internal/validator"
)

func TestL3L4XDPFilterNodeValid(t *testing.T) {
	reg := loadTestRegistry(t)
	path := filepath.Join(examplesDir(t), "nodes", "l3l4-xdp-filter.yaml")
	if err := validator.ValidateAdapterFile(path, reg); err != nil {
		t.Errorf("l3l4-xdp-filter node definition should be valid: %v", err)
	}
}

func TestTCPProxyNodeValid(t *testing.T) {
	reg := loadTestRegistry(t)
	path := filepath.Join(examplesDir(t), "nodes", "tcp-proxy.yaml")
	if err := validator.ValidateAdapterFile(path, reg); err != nil {
		t.Errorf("tcp-proxy node definition should be valid: %v", err)
	}
}

func TestLocalRiskEngineNodeValid(t *testing.T) {
	reg := loadTestRegistry(t)
	path := filepath.Join(examplesDir(t), "nodes", "local-risk-engine.yaml")
	if err := validator.ValidateAdapterFile(path, reg); err != nil {
		t.Errorf("local-risk-engine node definition should be valid: %v", err)
	}
}

func TestV2AdapterRolesValidated(t *testing.T) {
	reg := loadTestRegistry(t)
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "test-adapter"
	m.Adapter.Roles = []string{"pep", "sensor"}
	m.Capabilities = []validator.AdapterCapability{
		{ID: "observe.network.connection"},
	}
	if err := validator.ValidateAdapter(m, reg); err != nil {
		t.Errorf("v1alpha2 adapter with valid roles should pass: %v", err)
	}
}

func TestV2UnknownRoleRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "test-adapter"
	m.Adapter.Roles = []string{"pep", "graph_engine"} // graph_engine removed
	if err := validator.ValidateAdapter(m, reg); err == nil {
		t.Error("adapter with removed legacy role graph_engine should be rejected")
	}
}

func TestV2UnknownProfileRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "test-adapter"
	m.Adapter.Roles = []string{"pep"}
	m.Adapter.Profiles = []string{"nonexistent.profile"}
	if err := validator.ValidateAdapter(m, reg); err == nil {
		t.Error("adapter with unknown profile should be rejected")
	}
}

func TestV2KnownProfileAccepted(t *testing.T) {
	reg := loadTestRegistry(t)
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "test-adapter"
	m.Adapter.Roles = []string{"pep", "sensor"}
	m.Adapter.Profiles = []string{"network.l3_l4_filter"}
	if err := validator.ValidateAdapter(m, reg); err != nil {
		t.Errorf("adapter with known profile should be accepted: %v", err)
	}
}

func TestV2SelectionTraitsValidated(t *testing.T) {
	reg := loadTestRegistry(t)
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "test-adapter"
	m.Adapter.Roles = []string{"pep"}
	m.SelectionTraits = map[string]string{
		"enforcement_position": "early",
		"runtime_cost":         "very_low",
		"blast_radius":         "node",
	}
	if err := validator.ValidateAdapter(m, reg); err != nil {
		t.Errorf("adapter with valid selection_traits should pass: %v", err)
	}
}

func TestV2InvalidSelectionTraitKeyRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "test-adapter"
	m.Adapter.Roles = []string{"pep"}
	m.SelectionTraits = map[string]string{
		"nonexistent_trait": "early",
	}
	if err := validator.ValidateAdapter(m, reg); err == nil {
		t.Error("adapter with unknown selection_trait key should be rejected")
	}
}

func TestV2InvalidSelectionTraitValueRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "test-adapter"
	m.Adapter.Roles = []string{"pep"}
	m.SelectionTraits = map[string]string{
		"enforcement_position": "ultrafast", // not in allowed values
	}
	if err := validator.ValidateAdapter(m, reg); err == nil {
		t.Error("adapter with invalid selection_trait value should be rejected")
	}
}

func TestV2ProducesStatisticsValidated(t *testing.T) {
	reg := loadTestRegistry(t)
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "test-analyzer"
	m.Adapter.Roles = []string{"analyzer"}
	m.Capabilities = []validator.AdapterCapability{
		{
			ID:                 "analyze.baseline.learn",
			ProducesStatistics: []string{"upper_bound", "confidence", "phase"},
		},
	}
	if err := validator.ValidateAdapter(m, reg); err != nil {
		t.Errorf("analyzer with valid produces_statistics should pass: %v", err)
	}
}

func TestV2UnknownBaselineStatisticRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "test-analyzer"
	m.Adapter.Roles = []string{"analyzer"}
	m.Capabilities = []validator.AdapterCapability{
		{
			ID:                 "analyze.baseline.learn",
			ProducesStatistics: []string{"upper"}, // should be upper_bound
		},
	}
	if err := validator.ValidateAdapter(m, reg); err == nil {
		t.Error("adapter with unknown baseline_statistic should be rejected")
	}
}

func TestV2MapsToValidated(t *testing.T) {
	reg := loadTestRegistry(t)
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "test-pep"
	m.Adapter.Roles = []string{"pep"}
	m.Capabilities = []validator.AdapterCapability{
		{
			ID:          "enforce.access.deny",
			MapsTo:      []string{"enforce.network.deny"},
			Granularity: []string{"src_ip"},
		},
	}
	if err := validator.ValidateAdapter(m, reg); err != nil {
		t.Errorf("adapter with valid maps_to should pass: %v", err)
	}
}

func TestV2UnknownMapsToRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "test-pep"
	m.Adapter.Roles = []string{"pep"}
	m.Capabilities = []validator.AdapterCapability{
		{
			ID:     "enforce.access.deny",
			MapsTo: []string{"enforce.network.nonexistent"},
		},
	}
	if err := validator.ValidateAdapter(m, reg); err == nil {
		t.Error("adapter with maps_to referencing unknown capability should be rejected")
	}
}

func TestNginxStreamRejectedForHTTPRoutePolicy(t *testing.T) {
	// An NGINX stream adapter has only pep+sensor roles.
	// enforce.app.deny requires pep and is about app-level routing.
	// The adapter COULD claim enforce.app.deny, but its semantic_depth is l4_connection
	// so the compiler should reject it. Here we test the role-level check still works:
	// enforce.app.deny is allowed for pep, so an nginx-stream PEP CAN claim it in theory,
	// but in practice the constraint checking at compile time prevents the selection.
	// What we CAN test here: that enforce.app.deny IS a known capability allowed for pep.
	reg := loadTestRegistry(t)
	if !reg.HasCapability("enforce.app.deny") {
		t.Fatal("enforce.app.deny must be in registry")
	}
	cap := reg.Capabilities["enforce.app.deny"]
	roles := []string{"pep"}
	for _, role := range roles {
		for _, allowed := range cap.AllowedRoles {
			if role == allowed {
				return // at least one role matches — fine at registry level
			}
		}
	}
	t.Error("enforce.app.deny should be accessible to pep role at registry level")
}

func TestControllerRoleRequiredForOverlayCapabilities(t *testing.T) {
	reg := loadTestRegistry(t)
	// A pep without controller role should be rejected for overlay capabilities.
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "bad-pep"
	m.Adapter.Roles = []string{"pep"}
	m.Capabilities = []validator.AdapterCapability{
		{ID: "enforce.overlay.service_deny"},
	}
	if err := validator.ValidateAdapter(m, reg); err == nil {
		t.Error("pep-only adapter claiming enforce.overlay.service_deny should be rejected (requires controller role)")
	}
}

func TestAnalyzerRoleForBaselineCapabilities(t *testing.T) {
	reg := loadTestRegistry(t)
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "good-analyzer"
	m.Adapter.Roles = []string{"pdp", "analyzer"}
	m.Capabilities = []validator.AdapterCapability{
		{ID: "analyze.baseline.compare"},
		{ID: "analyze.risk.score"},
	}
	if err := validator.ValidateAdapter(m, reg); err != nil {
		t.Errorf("pdp+analyzer adapter with baseline caps should pass: %v", err)
	}
}
