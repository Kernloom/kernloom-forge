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
	if len(reg.ComponentRoles) == 0 {
		t.Error("no component_roles loaded")
	}
	if len(reg.ComponentProfiles) == 0 {
		t.Error("no component_profiles loaded")
	}
	if len(reg.BaselineStatistics) == 0 {
		t.Error("no baseline_statistics loaded")
	}
	if len(reg.SelectionTraits) == 0 {
		t.Error("no selection_traits loaded")
	}
	if len(reg.CompilerRules) == 0 {
		t.Error("no compiler_rules loaded")
	}
}

func TestKnownRoles(t *testing.T) {
	reg, err := registry.LoadDir(coreRegistryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"pep", "sensor", "analyzer", "pdp", "pip", "controller", "sink"} {
		if !reg.HasComponentRole(id) {
			t.Errorf("expected role %q to be present", id)
		}
	}
}

func TestRemovedLegacyRolesAbsent(t *testing.T) {
	reg, err := registry.LoadDir(coreRegistryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"graph_engine", "overlay_controller", "app_gateway", "platform_adapter"} {
		if reg.HasComponentRole(id) {
			t.Errorf("legacy role %q should not be present in the simplified adapter types", id)
		}
	}
}

func TestKnownComponentProfiles(t *testing.T) {
	reg, err := registry.LoadDir(coreRegistryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"network.l3_l4_filter",
		"network.transport_proxy",
		"app.http_gateway",
		"overlay.controller_api",
		"analysis.behavior_baseline",
		"analysis.relation_graph",
		"decision.local_pdp",
		"decision.global_pdp",
		"control.local_adapter_manager",
		"telemetry.sink",
	} {
		if !reg.HasComponentProfile(id) {
			t.Errorf("expected component_profile %q to be present", id)
		}
	}
}

func TestKnownBaselineStatistics(t *testing.T) {
	reg, err := registry.LoadDir(coreRegistryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"expected", "lower_bound", "upper_bound",
		"deviation_ratio", "confidence", "phase",
		"sample_count", "window_seconds", "model_id", "model_version",
	} {
		if !reg.HasBaselineStatistic(id) {
			t.Errorf("expected baseline_statistic %q to be present", id)
		}
	}
}

func TestKnownSelectionTraits(t *testing.T) {
	reg, err := registry.LoadDir(coreRegistryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"enforcement_position", "runtime_cost", "semantic_precision",
		"identity_awareness", "app_awareness", "source_attribution",
		"convergence_speed", "blast_radius",
	} {
		if !reg.HasSelectionTrait(id) {
			t.Errorf("expected selection_trait %q to be present", id)
		}
	}
}

func TestKnownIntents(t *testing.T) {
	reg, err := registry.LoadDir(coreRegistryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		// Core intents.
		"access.relation.allow",
		"access.relation.default_deny",
		"protection.source.quarantine",
		"protection.dos.prevent",
		"protection.dos.mitigate",
		"protection.abuse.mitigate",
		// New generic relation intents.
		"relation.learn",
		"relation.freeze",
		"relation.enforce_known_only",
		// Legacy microsegmentation — kept for backward compatibility.
		"microsegmentation.learn",
		"microsegmentation.freeze",
		// Telemetry.
		"telemetry.export",
		"telemetry.alert",
	} {
		if !reg.HasIntent(id) {
			t.Errorf("expected intent %q to be present", id)
		}
	}
}

func TestKnownSignals(t *testing.T) {
	reg, err := registry.LoadDir(coreRegistryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"network.metric.connections_per_second",
		"baseline.expected",
		"baseline.upper_bound",
		"baseline.lower_bound",
		"baseline.deviation_ratio",
		"baseline.confidence",
		"baseline.phase",
		"anomaly.score",
		"anomaly.severity",
		"anomaly.confidence",
		"risk.score",
		"risk.level",
		"risk.confidence",
		"tls.sni",
		"tls.alpn",
	} {
		if !reg.HasSignal(id) {
			t.Errorf("expected signal %q to be present", id)
		}
	}
}

func TestKnownGenericCapabilities(t *testing.T) {
	reg, err := registry.LoadDir(coreRegistryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"observe.network.connection",
		"observe.tls.client_hello",
		"enforce.access.allow",
		"enforce.access.deny",
		"enforce.access.default_deny",
		"enforce.traffic.rate_limit",
		"enforce.traffic.connection_limit",
		"enforce.traffic.bandwidth_limit",
		"enforce.traffic.drop",
		"route.traffic.forward",
		"analyze.baseline.compare",
		"analyze.risk.score",
		"export.telemetry",
	} {
		if !reg.HasCapability(id) {
			t.Errorf("expected capability %q to be present", id)
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

func TestGranularityGroupsPresent(t *testing.T) {
	reg, err := registry.LoadDir(coreRegistryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"connection_id", "listener_id", "upstream_id", "flow_id"} {
		if !reg.HasGranularity(id) {
			t.Errorf("expected granularity %q to be present", id)
		}
	}
	// Verify group field is populated.
	if g, ok := reg.Granularities["src_ip"]; !ok || g.Group == "" {
		t.Error("src_ip granularity should have a group")
	}
}
