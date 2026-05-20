// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package validator_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kernloom/kernloom-forge/internal/registry"
	"github.com/kernloom/kernloom-forge/internal/validator"
)

func loadTestRegistry(t *testing.T) *registry.Registry {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	reg, err := registry.LoadDir(filepath.Join(root, "registries", "core"))
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	return reg
}

func examplesDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "examples")
}

func adaptersDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "registries", "adapters")
}

func TestL3L4XDPFilterDefinitionValid(t *testing.T) {
	reg := loadTestRegistry(t)
	path := filepath.Join(adaptersDir(t), "klshield.yaml")
	if err := validator.ValidateAdapterFile(path, reg); err != nil {
		t.Errorf("klshield adapter definition should be valid: %v", err)
	}
}

func TestFakePEPWithUnknownCapabilityRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "fake-pep"
	m.Adapter.Types = []string{"pep"}
	m.Capabilities = []validator.AdapterCapability{
		{ID: "magic.block.everything"},
	}
	if err := validator.ValidateAdapter(m, reg); err == nil {
		t.Error("adapter with unknown capability should be rejected")
	}
}

func TestAdapterWithWrongTypeForCapabilityRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	// analyze.relation.learn is only allowed for analyzer, not pep.
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "bad-pep"
	m.Adapter.Types = []string{"pep"}
	m.Capabilities = []validator.AdapterCapability{
		{ID: "analyze.relation.learn"},
	}
	if err := validator.ValidateAdapter(m, reg); err == nil {
		t.Error("pep adapter claiming analyze.relation.learn should be rejected")
	}
}

func TestExtensionCapabilityRejectedInStrictMode(t *testing.T) {
	reg := loadTestRegistry(t)
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "ext-adapter"
	m.Adapter.Types = []string{"sensor"}
	m.Capabilities = []validator.AdapterCapability{
		{ID: "x.vendor.custom_observe"},
	}
	if err := validator.ValidateAdapter(m, reg); err == nil {
		t.Error("extension capability should be rejected in strict mode")
	}
}

func TestUnknownSignalProducedRejected(t *testing.T) {
	reg := loadTestRegistry(t)
	m := &validator.NodeDefinition{}
	m.Metadata.ID = "bad-sensor"
	m.Adapter.Types = []string{"sensor"}
	m.SignalsProduced = []string{"x.fake.unknown_signal"}
	if err := validator.ValidateAdapter(m, reg); err == nil {
		t.Error("adapter producing unknown signal should be rejected")
	}
}
