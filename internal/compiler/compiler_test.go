// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package compiler_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kernloom/kernloom-forge/internal/compiler"
	"github.com/kernloom/kernloom-forge/internal/registry"
	"github.com/kernloom/kernloom-forge/internal/validator"
)

// ── Test helpers ─────────────────────────────────────────────────────────────

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func loadReg(t *testing.T) *registry.Registry {
	t.Helper()
	reg, err := registry.LoadDir(filepath.Join(repoRoot(t), "registries", "core"))
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	return reg
}

func loadExampleNodes(t *testing.T, reg *registry.Registry) []validator.NodeDefinition {
	t.Helper()
	nodes, err := validator.LoadNodeDefinitionsFromDir(filepath.Join(repoRoot(t), "registries", "adapters"), reg)
	if err != nil {
		t.Fatalf("load example nodes: %v", err)
	}
	return nodes
}

func loadExamplePolicy(t *testing.T, reg *registry.Registry, name string) validator.Policy {
	t.Helper()
	p, err := validator.ParsePolicyFile(filepath.Join(repoRoot(t), "examples", "policies", name))
	if err != nil {
		t.Fatalf("parse policy %s: %v", name, err)
	}
	if err := validator.ValidatePolicy(&p, reg); err != nil {
		t.Fatalf("validate policy %s: %v", name, err)
	}
	return p
}

// buildNode constructs a minimal NodeDefinition for unit tests.
func buildNode(id string, roles []string, caps []validator.AdapterCapability, traits map[string]string) validator.NodeDefinition {
	n := validator.NodeDefinition{}
	n.Metadata.ID = id
	n.Adapter.Roles = roles
	n.Capabilities = caps
	n.SelectionTraits = traits
	return n
}

func capID(id string, granularity ...string) validator.AdapterCapability {
	return validator.AdapterCapability{ID: id, Granularity: granularity}
}

func capScoped(id string, scopes ...string) validator.AdapterCapability {
	return validator.AdapterCapability{ID: id, Scopes: scopes}
}

func hasCap(caps []string, id string) bool {
	for _, c := range caps {
		if c == id {
			return true
		}
	}
	return false
}

func hasNodeID(nodes interface{ getIDs() []string }, id string) bool {
	for _, v := range nodes.getIDs() {
		if v == id {
			return true
		}
	}
	return false
}

// ── Integration tests — real examples ────────────────────────────────────────

func TestCompileMitigateConnectionSpike(t *testing.T) {
	reg := loadReg(t)
	nodes := loadExampleNodes(t, reg)
	policy := loadExamplePolicy(t, reg, "mitigate-connection-spike.yaml")

	result, err := compiler.CompilePolicy(compiler.CompileRequest{Policy: policy, Nodes: nodes}, reg)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if result.Status != compiler.StatusSuccess {
		t.Fatalf("expected %q, got %q — missing: %v", compiler.StatusSuccess, result.Status, result.Missing)
	}

	// Enforcer must be selected for enforce.traffic.rate_limit.
	if len(result.SelectedPlan.Enforcers) == 0 {
		t.Error("expected at least one enforcer in selected plan")
	}
	enforcerOK := false
	for _, e := range result.SelectedPlan.Enforcers {
		if e.NodeID == "klshield" {
			enforcerOK = true
		}
	}
	if !enforcerOK {
		t.Errorf("klshield not selected as enforcer; got: %v", result.SelectedPlan.Enforcers)
	}

	// tcp-proxy should be a fallback (can do observe.network.connection but not rate_limit).
	tcpProxyFallback := false
	for _, f := range result.Fallbacks {
		if f.NodeID == "tcp-proxy" {
			tcpProxyFallback = true
		}
	}
	if !tcpProxyFallback {
		t.Errorf("expected tcp-proxy as fallback; fallbacks: %v", result.Fallbacks)
	}
}

func TestCompileDOSPrevention(t *testing.T) {
	reg := loadReg(t)
	nodes := loadExampleNodes(t, reg)
	policy := loadExamplePolicy(t, reg, "dos-prevention.yaml")

	result, err := compiler.CompilePolicy(compiler.CompileRequest{Policy: policy, Nodes: nodes}, reg)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	// dos-prevention uses only rate_limit — success or partial match expected.
	if result.PolicyID != "dos-prevention" {
		t.Errorf("unexpected policy ID %q", result.PolicyID)
	}
}

func TestCompileResultIsValidYAML(t *testing.T) {
	reg := loadReg(t)
	nodes := loadExampleNodes(t, reg)
	policy := loadExamplePolicy(t, reg, "mitigate-connection-spike.yaml")

	result, err := compiler.CompilePolicy(compiler.CompileRequest{Policy: policy, Nodes: nodes}, reg)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	out, err := yaml.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(out) == 0 {
		t.Error("empty YAML output")
	}
}

// ── Unit tests — in-code fixtures ────────────────────────────────────────────

func TestCompileSelectsHighestScoringNode(t *testing.T) {
	reg := loadReg(t)

	highScore := buildNode("high", []string{"pep"}, []validator.AdapterCapability{
		capID("enforce.access.deny", "src_ip", "tuple_5"),
	}, map[string]string{
		"enforcement_position": "early",
		"runtime_cost":         "very_low",
		"source_attribution":   "strong",
		"blast_radius":         "node",
		"convergence_speed":    "immediate",
	})
	lowScore := buildNode("low", []string{"pep"}, []validator.AdapterCapability{
		capID("enforce.access.deny", "src_ip"),
	}, map[string]string{
		"enforcement_position": "late",
		"runtime_cost":         "high",
		"source_attribution":   "weak",
		"blast_radius":         "global",
		"convergence_speed":    "eventual",
	})

	policy := validator.Policy{Kind: "RuntimePolicy"}
	policy.Metadata.ID = "test-scoring"
	policy.Requirements = validator.PolicyRequirements{
		RequiredCapabilities: []string{"enforce.access.deny"},
		MinGranularity:       []string{"src_ip"},
	}

	// Intentionally pass low-score node first to verify score-based sorting.
	result, err := compiler.CompilePolicy(compiler.CompileRequest{
		Policy: policy, Nodes: []validator.NodeDefinition{lowScore, highScore},
	}, reg)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if result.Status != compiler.StatusSuccess {
		t.Fatalf("expected success, got %q", result.Status)
	}
	if len(result.SelectedPlan.Enforcers) == 0 {
		t.Fatal("no enforcer selected")
	}
	if result.SelectedPlan.Enforcers[0].NodeID != "high" {
		t.Errorf("expected 'high' node to be selected, got %q", result.SelectedPlan.Enforcers[0].NodeID)
	}

	// Low-score node should appear as fallback.
	fallbackFound := false
	for _, f := range result.Fallbacks {
		if f.NodeID == "low" {
			fallbackFound = true
		}
	}
	if !fallbackFound {
		t.Error("expected low-score node to be a fallback")
	}
}

func TestCompileAnalyzerSeparatedFromEnforcer(t *testing.T) {
	reg := loadReg(t)

	analyzer := buildNode("analyzer-node", []string{"pdp", "analyzer"}, []validator.AdapterCapability{
		{ID: "analyze.baseline.compare", SupportedScopes: []string{"global", "src_ip"}},
	}, map[string]string{"enforcement_position": "control_plane", "runtime_cost": "low"})

	enforcer := buildNode("enforcer-node", []string{"pep"}, []validator.AdapterCapability{
		capID("enforce.traffic.rate_limit", "src_ip", "tuple_5"),
		capScoped("observe.network.connection", "src_ip"),
	}, map[string]string{"enforcement_position": "early", "runtime_cost": "very_low"})

	policy := validator.Policy{Kind: "RuntimePolicy"}
	policy.Metadata.ID = "test-split"
	policy.Requirements = validator.PolicyRequirements{
		RequiredCapabilities: []string{
			"observe.network.connection",
			"analyze.baseline.compare",
			"enforce.traffic.rate_limit",
		},
		MinGranularity: []string{"src_ip"},
	}

	result, err := compiler.CompilePolicy(compiler.CompileRequest{
		Policy: policy, Nodes: []validator.NodeDefinition{analyzer, enforcer},
	}, reg)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if result.Status != compiler.StatusSuccess {
		t.Fatalf("expected success, got %q — missing: %v", result.Status, result.Missing)
	}
	if len(result.SelectedPlan.Analyzers) != 1 || result.SelectedPlan.Analyzers[0].NodeID != "analyzer-node" {
		t.Errorf("expected analyzer-node in analyzers, got %v", result.SelectedPlan.Analyzers)
	}
	if len(result.SelectedPlan.Enforcers) != 1 || result.SelectedPlan.Enforcers[0].NodeID != "enforcer-node" {
		t.Errorf("expected enforcer-node in enforcers, got %v", result.SelectedPlan.Enforcers)
	}
}

func TestCompileNoSilentDowngrade(t *testing.T) {
	reg := loadReg(t)

	coarse := buildNode("coarse-pep", []string{"pep"}, []validator.AdapterCapability{
		capID("enforce.access.deny", "global"), // only global, not src_ip
	}, map[string]string{"enforcement_position": "early"})

	policy := validator.Policy{Kind: "RuntimePolicy"}
	policy.Metadata.ID = "test-no-downgrade"
	policy.Requirements = validator.PolicyRequirements{
		RequiredCapabilities: []string{"enforce.access.deny"},
		MinGranularity:       []string{"src_ip"},
	}
	policy.Requirements.Degradation.Allow = false

	result, err := compiler.CompilePolicy(compiler.CompileRequest{
		Policy: policy, Nodes: []validator.NodeDefinition{coarse},
	}, reg)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if result.Status != compiler.StatusUnsupported {
		t.Errorf("expected unsupported (no silent downgrade), got %q", result.Status)
	}
	if !hasCap(result.Missing.Capabilities, "enforce.access.deny") {
		t.Errorf("expected enforce.access.deny in missing, got %v", result.Missing)
	}
}

func TestCompileDegradationAllowed(t *testing.T) {
	reg := loadReg(t)

	coarse := buildNode("coarse-pep", []string{"pep"}, []validator.AdapterCapability{
		capID("enforce.access.deny", "global"),
	}, map[string]string{"enforcement_position": "early"})

	policy := validator.Policy{Kind: "RuntimePolicy"}
	policy.Metadata.ID = "test-degradation"
	policy.Requirements = validator.PolicyRequirements{
		RequiredCapabilities: []string{"enforce.access.deny"},
		MinGranularity:       []string{"src_ip"},
	}
	policy.Requirements.Degradation.Allow = true

	result, err := compiler.CompilePolicy(compiler.CompileRequest{
		Policy: policy, Nodes: []validator.NodeDefinition{coarse},
	}, reg)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if result.Status != compiler.StatusSuccess {
		t.Errorf("expected success with degradation.allow=true, got %q (missing: %v)", result.Status, result.Missing)
	}
}

func TestCompileMissingCapabilityReported(t *testing.T) {
	reg := loadReg(t)

	observer := buildNode("observer", []string{"sensor"}, []validator.AdapterCapability{
		capScoped("observe.network.connection", "src_ip"),
	}, nil)

	policy := validator.Policy{Kind: "RuntimePolicy"}
	policy.Metadata.ID = "test-missing"
	policy.Requirements = validator.PolicyRequirements{
		RequiredCapabilities: []string{
			"observe.network.connection",
			"enforce.access.deny", // no node has this
		},
	}

	result, err := compiler.CompilePolicy(compiler.CompileRequest{
		Policy: policy, Nodes: []validator.NodeDefinition{observer},
	}, reg)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if result.Status != compiler.StatusUnsupported {
		t.Errorf("expected unsupported, got %q", result.Status)
	}
	if !hasCap(result.Missing.Capabilities, "enforce.access.deny") {
		t.Errorf("expected enforce.access.deny in missing, got %v", result.Missing.Capabilities)
	}
}

func TestCompileFallsBackToThenActions(t *testing.T) {
	reg := loadReg(t)

	pep := buildNode("pep", []string{"pep"}, []validator.AdapterCapability{
		capID("enforce.access.deny", "src_ip"),
	}, map[string]string{"enforcement_position": "early"})

	// Policy with no requirements — only then: capability_action.
	policy := validator.Policy{Kind: "RuntimePolicy"}
	policy.Metadata.ID = "test-then-fallback"
	policy.Then = []validator.PolicyAction{
		{Type: "capability_action", Capability: "enforce.access.deny"},
	}

	result, err := compiler.CompilePolicy(compiler.CompileRequest{
		Policy: policy, Nodes: []validator.NodeDefinition{pep},
	}, reg)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if result.Status != compiler.StatusSuccess {
		t.Errorf("expected success using then: as fallback requirements, got %q", result.Status)
	}
	if len(result.SelectedPlan.Enforcers) == 0 {
		t.Error("expected pep to be selected as enforcer")
	}
}

func TestCompileEmptyNodesUnsupported(t *testing.T) {
	reg := loadReg(t)

	policy := validator.Policy{Kind: "RuntimePolicy"}
	policy.Metadata.ID = "test-empty-nodes"
	policy.Requirements = validator.PolicyRequirements{
		RequiredCapabilities: []string{"enforce.access.deny"},
	}

	result, err := compiler.CompilePolicy(compiler.CompileRequest{
		Policy: policy, Nodes: nil,
	}, reg)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if result.Status != compiler.StatusUnsupported {
		t.Errorf("expected unsupported with no nodes, got %q", result.Status)
	}
}

func TestCompileHTTPRouteRejectedByL4Nodes(t *testing.T) {
	reg := loadReg(t)
	nodes := loadExampleNodes(t, reg)

	// No example node has observe.app.request or enforce.app.deny.
	policy := validator.Policy{Kind: "RuntimePolicy"}
	policy.Metadata.ID = "test-http-route"
	policy.Requirements = validator.PolicyRequirements{
		RequiredCapabilities: []string{"observe.app.request", "enforce.app.deny"},
		MinGranularity:       []string{"route", "subject_id"},
	}

	result, err := compiler.CompilePolicy(compiler.CompileRequest{Policy: policy, Nodes: nodes}, reg)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if result.Status != compiler.StatusUnsupported {
		t.Errorf("expected unsupported (no HTTP gateway node registered), got %q", result.Status)
	}
	if len(result.Missing.Capabilities) == 0 {
		t.Error("expected missing capabilities to be reported")
	}
}
