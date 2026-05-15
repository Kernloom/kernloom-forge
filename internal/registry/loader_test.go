// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package registry_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kernloom/kernloom-forge/internal/registry"
)

func coreRegistryPath(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	// file = .../internal/registry/loader_test.go
	// root = ../../..
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "registries", "core")
}

func TestLoadCoreRegistry(t *testing.T) {
	reg, err := registry.LoadDir(coreRegistryPath(t))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	if len(reg.Intents) == 0 {
		t.Error("no intents loaded")
	}
	if len(reg.Capabilities) == 0 {
		t.Error("no capabilities loaded")
	}
	if len(reg.Signals) == 0 {
		t.Error("no signals loaded")
	}
	if len(reg.Granularities) == 0 {
		t.Error("no granularities loaded")
	}
	if len(reg.AdapterTypes) == 0 {
		t.Error("no adapter_types loaded")
	}
	if len(reg.CompilerRules) == 0 {
		t.Error("no compiler_rules loaded")
	}
}

func TestKnownIntents(t *testing.T) {
	reg, err := registry.LoadDir(coreRegistryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"access.relation.allow",
		"access.relation.default_deny",
		"protection.source.quarantine",
		"protection.dos.prevent",
		"microsegmentation.learn",
		"microsegmentation.freeze",
	} {
		if !reg.HasIntent(id) {
			t.Errorf("expected intent %q to be present", id)
		}
	}
}

func TestUnknownCapabilityRejected(t *testing.T) {
	reg, err := registry.LoadDir(coreRegistryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if reg.HasCapability("magic.block.everything") {
		t.Error("unknown capability should not be present")
	}
}

func TestUnknownSignalRejected(t *testing.T) {
	reg, err := registry.LoadDir(coreRegistryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if reg.HasSignal("x.fake.signal") {
		t.Error("unknown signal should not be present")
	}
}

func TestCompilerRulesCoverAllIntents(t *testing.T) {
	reg, err := registry.LoadDir(coreRegistryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	covered := make(map[string]bool)
	for _, rule := range reg.CompilerRules {
		covered[rule.Intent] = true
	}
	for id := range reg.Intents {
		if !covered[id] {
			t.Errorf("intent %q has no compiler rule", id)
		}
	}
}
