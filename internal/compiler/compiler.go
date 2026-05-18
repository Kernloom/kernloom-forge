// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package compiler compiles Forge policies against registered node definitions
// and produces a CompilerDecisionReport explaining which nodes were selected,
// which are fallbacks, and which capabilities could not be satisfied.
package compiler

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kernloom/kernloom-forge/internal/registry"
	"github.com/kernloom/kernloom-forge/internal/validator"
)

// Status values for CompileResult.
const (
	StatusSuccess     = "success"
	StatusUnsupported = "unsupported"
)

// CompileRequest is the input to CompilePolicy.
type CompileRequest struct {
	Policy validator.Policy
	Nodes  []validator.NodeDefinition
}

// SelectedNode is a node chosen as primary provider for one or more capabilities.
type SelectedNode struct {
	NodeID       string   `yaml:"node_id"`
	Capabilities []string `yaml:"capabilities"`
	Score        int      `yaml:"score"`
	Reason       string   `yaml:"reason"`
}

// FallbackNode is a node that can satisfy some required capabilities but was not
// chosen as the primary candidate (a higher-scoring node was preferred).
type FallbackNode struct {
	NodeID       string   `yaml:"node_id"`
	Capabilities []string `yaml:"capabilities"`
	Score        int      `yaml:"score"`
	Reason       string   `yaml:"reason"`
}

// RejectedNode is a node that could not satisfy any required capability.
type RejectedNode struct {
	NodeID  string   `yaml:"node_id"`
	Reasons []string `yaml:"reasons"`
}

// CompiledPlan contains the nodes selected to execute the policy, split by function.
// Analyzers provide analyze.* capabilities; Enforcers provide enforce.*/observe.*/route.*.
type CompiledPlan struct {
	Analyzers []SelectedNode `yaml:"analyzers,omitempty"`
	Enforcers []SelectedNode `yaml:"enforcers,omitempty"`
}

// MissingRequirements lists capabilities that no registered node could satisfy.
type MissingRequirements struct {
	Capabilities []string `yaml:"capabilities,omitempty"`
}

// CompileResult is the CompilerDecisionReport produced by CompilePolicy.
type CompileResult struct {
	Kind          string              `yaml:"kind"`
	APIVersion    string              `yaml:"apiVersion"`
	Status        string              `yaml:"status"`
	PolicyID      string              `yaml:"policy_id"`
	SelectedPlan  CompiledPlan        `yaml:"selected_plan,omitempty"`
	Fallbacks     []FallbackNode      `yaml:"fallbacks,omitempty"`
	RejectedNodes []RejectedNode      `yaml:"rejected_nodes,omitempty"`
	Missing       MissingRequirements `yaml:"missing,omitempty"`
	Warnings      []string            `yaml:"warnings,omitempty"`
}

// nodeEval is the internal result of matching one node against the policy requirements.
type nodeEval struct {
	node          validator.NodeDefinition
	matchedCaps   []string // capabilities this node CAN satisfy
	rejectReasons []string // reasons why required capabilities could not be matched
	score         int
}

// CompilePolicy compiles a policy against a set of registered node definitions.
//
// Algorithm:
//  1. Collect required capabilities from requirements + then[] actions.
//  2. Evaluate each node: hard-check required capabilities and min_granularity.
//  3. Determine which capabilities are satisfiable (at least one node qualifies).
//  4. If any capability is unsatisfiable → status: unsupported with Missing populated.
//  5. Greedy assignment: for each capability, pick the highest-scoring node that can provide it.
//  6. Split selected nodes into Analyzers (analyze.*) and Enforcers (everything else).
//  7. Nodes with partial matches that weren't selected as primary → Fallbacks.
//  8. Nodes with no matching capability → RejectedNodes.
func CompilePolicy(req CompileRequest, reg *registry.Registry) (*CompileResult, error) {
	_ = reg // reserved for future semantic_depth and registry cross-checks

	// Normalize so spec.requirements and spec.rules are populated regardless of source format.
	req.Policy.Normalize()

	required, warn := collectRequiredCapabilities(req.Policy)
	minGran := req.Policy.Spec.Requirements.MinGranularity
	if len(minGran) == 0 {
		minGran = req.Policy.Requirements.MinGranularity
	}
	degradationAllowed := req.Policy.Spec.Requirements.Degradation.Allow || req.Policy.Requirements.Degradation.Allow

	result := &CompileResult{
		Kind:       "CompilerDecisionReport",
		APIVersion: "forge.kernloom.io/v1alpha2",
		PolicyID:   req.Policy.Metadata.ID,
	}
	if warn != "" {
		result.Warnings = append(result.Warnings, warn)
	}
	if len(required) == 0 {
		result.Status = StatusUnsupported
		result.Missing = MissingRequirements{Capabilities: []string{"(none declared)"}}
		return result, nil
	}

	// Evaluate every node against the required capabilities.
	evals := make([]nodeEval, 0, len(req.Nodes))
	for _, node := range req.Nodes {
		evals = append(evals, evaluateNode(node, required, minGran, degradationAllowed))
	}

	// Check which required capabilities are satisfiable by at least one node.
	satisfiable := make(map[string]bool, len(required))
	for _, capID := range required {
		for _, ev := range evals {
			if containsStr(ev.matchedCaps, capID) {
				satisfiable[capID] = true
				break
			}
		}
	}

	var missing []string
	for _, capID := range required {
		if !satisfiable[capID] {
			missing = append(missing, capID)
		}
	}
	if len(missing) > 0 {
		result.Status = StatusUnsupported
		result.Missing = MissingRequirements{Capabilities: missing}
		for _, ev := range evals {
			if len(ev.rejectReasons) > 0 {
				result.RejectedNodes = append(result.RejectedNodes, RejectedNode{
					NodeID:  ev.node.Metadata.ID,
					Reasons: ev.rejectReasons,
				})
			}
		}
		return result, nil
	}

	// All capabilities satisfiable — greedy assignment by score.
	sort.Slice(evals, func(i, j int) bool { return evals[i].score > evals[j].score })

	capToNode := make(map[string]string)    // capID → nodeID of primary provider
	nodeToCaps := make(map[string][]string) // nodeID → caps assigned to it
	nodeScores := make(map[string]int)

	for _, capID := range required {
		for _, ev := range evals {
			if containsStr(ev.matchedCaps, capID) {
				nodeID := ev.node.Metadata.ID
				if _, alreadyAssigned := capToNode[capID]; !alreadyAssigned {
					capToNode[capID] = nodeID
					nodeToCaps[nodeID] = append(nodeToCaps[nodeID], capID)
					nodeScores[nodeID] = ev.score
				}
			}
		}
	}

	selectedIDs := make(map[string]bool)
	for _, id := range capToNode {
		selectedIDs[id] = true
	}

	var analyzers, enforcers []SelectedNode
	for id := range selectedIDs {
		caps := nodeToCaps[id]
		sn := SelectedNode{
			NodeID:       id,
			Capabilities: caps,
			Score:        nodeScores[id],
			Reason:       fmt.Sprintf("provides %s", strings.Join(caps, ", ")),
		}
		if allAnalyze(caps) {
			analyzers = append(analyzers, sn)
		} else {
			enforcers = append(enforcers, sn)
		}
	}
	sortSelectedByScore(analyzers)
	sortSelectedByScore(enforcers)

	// Nodes not selected as primary → fallback (partial match) or rejected (no match).
	var fallbacks []FallbackNode
	var rejected []RejectedNode

	for _, ev := range evals {
		id := ev.node.Metadata.ID
		if selectedIDs[id] {
			continue
		}
		shared := intersect(ev.matchedCaps, required)
		if len(shared) > 0 {
			fallbacks = append(fallbacks, FallbackNode{
				NodeID:       id,
				Capabilities: shared,
				Score:        ev.score,
				Reason:       fmt.Sprintf("alternative provider for %s", strings.Join(shared, ", ")),
			})
		} else {
			rejected = append(rejected, RejectedNode{
				NodeID:  id,
				Reasons: ev.rejectReasons,
			})
		}
	}

	result.Status = StatusSuccess
	result.SelectedPlan = CompiledPlan{Analyzers: analyzers, Enforcers: enforcers}
	result.Fallbacks = fallbacks
	result.RejectedNodes = rejected
	return result, nil
}

// collectRequiredCapabilities gathers all capability IDs the policy needs.
// Reads from canonical spec.requirements.capabilities first, falls back to
// legacy requirements.required_capabilities and spec.rules[].effects[].
func collectRequiredCapabilities(policy validator.Policy) (caps []string, warning string) {
	seen := make(map[string]bool)
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			caps = append(caps, id)
		}
	}

	// Canonical form: spec.requirements.capabilities
	for _, capID := range policy.Spec.Requirements.Capabilities {
		add(capID)
	}
	// Legacy form: spec.requirements.required_capabilities
	for _, capID := range policy.Spec.Requirements.RequiredCapabilities {
		add(capID)
	}
	// Legacy top-level requirements block
	for _, capID := range policy.Requirements.RequiredCapabilities {
		add(capID)
	}
	// Fallback: derive from spec.rules[].effects[].action
	for _, rule := range policy.Spec.Rules {
		for _, effect := range rule.Effects {
			if effect.Type == "action" {
				capID := effect.Action
				if capID == "" {
					capID = effect.Capability
				}
				add(capID)
			}
		}
	}
	if len(caps) == 0 {
		warning = "policy has no requirements.capabilities and no action effects — nothing to compile"
	}
	return caps, warning
}

// evaluateNode checks which required capabilities a node can satisfy, performing
// hard granularity checks. Respects degradation.allow for granularity mismatches.
func evaluateNode(
	node validator.NodeDefinition,
	required []string,
	minGranularity []string,
	degradationAllowed bool,
) nodeEval {
	ev := nodeEval{
		node:  node,
		score: scoreNode(node),
	}

	// Build lookup from all declared capabilities (including optional).
	nodeCaps := make(map[string]*validator.AdapterCapability, len(node.Capabilities)+len(node.OptionalCapabilities))
	for i := range node.Capabilities {
		ac := &node.Capabilities[i]
		nodeCaps[ac.ID] = ac
	}
	for i := range node.OptionalCapabilities {
		ac := &node.OptionalCapabilities[i]
		if _, exists := nodeCaps[ac.ID]; !exists {
			nodeCaps[ac.ID] = ac
		}
	}

	for _, capID := range required {
		ac, ok := nodeCaps[capID]
		if !ok {
			ev.rejectReasons = append(ev.rejectReasons, fmt.Sprintf("missing capability %q", capID))
			continue
		}

		// Granularity / scope check.
		if len(minGranularity) > 0 {
			available := capDimensions(ac)
			// If the capability declares no dimensions at all it is treated as unconstrained.
			if len(available) > 0 && !anyIn(minGranularity, available) {
				if !degradationAllowed {
					ev.rejectReasons = append(ev.rejectReasons,
						fmt.Sprintf("capability %q cannot satisfy min_granularity %v (available: %v)",
							capID, minGranularity, available))
					continue
				}
				// degradation allowed — accept with coarser precision, no explicit warning here
			}
		}

		ev.matchedCaps = append(ev.matchedCaps, capID)
	}

	if len(ev.matchedCaps) == 0 && len(ev.rejectReasons) == 0 {
		ev.rejectReasons = append(ev.rejectReasons, "no required capabilities declared by this node")
	}
	return ev
}

// capDimensions aggregates all granularity/scope fields from a capability entry.
// Enforcers use Granularity; observers use Scopes; analyzers use SupportedScopes.
func capDimensions(ac *validator.AdapterCapability) []string {
	var out []string
	out = append(out, ac.Granularity...)
	out = append(out, ac.Scopes...)
	out = append(out, ac.SupportedScopes...)
	return out
}

// scoreNode computes a ranking score from the node's selection_traits.
// Higher score = preferred primary candidate. Weights follow the v2 spec:
//
//	enforcement_position: early(30) mid(20) late(10) control_plane(0)
//	runtime_cost:         very_low(20) low(15) medium(5) high(0)
//	source_attribution:   strong(20) conditional(10) weak(0)
//	blast_radius:         packet(10)…global(0)
//	convergence_speed:    immediate(10) fast(5) eventual(0)
func scoreNode(node validator.NodeDefinition) int {
	t := node.SelectionTraits
	score := 0

	switch t["enforcement_position"] {
	case "early":
		score += 30
	case "mid":
		score += 20
	case "late":
		score += 10
	}

	switch t["runtime_cost"] {
	case "very_low":
		score += 20
	case "low":
		score += 15
	case "medium":
		score += 5
	}

	switch t["source_attribution"] {
	case "strong":
		score += 20
	case "conditional":
		score += 10
	}

	switch t["blast_radius"] {
	case "packet":
		score += 10
	case "flow":
		score += 8
	case "listener":
		score += 6
	case "node":
		score += 4
	case "service":
		score += 2
	case "tenant":
		score += 1
	}

	switch t["convergence_speed"] {
	case "immediate":
		score += 10
	case "fast":
		score += 5
	}

	return score
}

// allAnalyze returns true if every capability starts with "analyze.".
func allAnalyze(caps []string) bool {
	if len(caps) == 0 {
		return false
	}
	for _, c := range caps {
		if !strings.HasPrefix(c, "analyze.") {
			return false
		}
	}
	return true
}

func sortSelectedByScore(nodes []SelectedNode) {
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Score > nodes[j].Score })
}

// anyIn returns true if any element of targets appears in available.
func anyIn(targets, available []string) bool {
	set := make(map[string]bool, len(available))
	for _, v := range available {
		set[v] = true
	}
	for _, t := range targets {
		if set[t] {
			return true
		}
	}
	return false
}

// intersect returns elements that appear in both a and b.
func intersect(a, b []string) []string {
	bSet := make(map[string]bool, len(b))
	for _, v := range b {
		bSet[v] = true
	}
	var result []string
	for _, v := range a {
		if bSet[v] {
			result = append(result, v)
		}
	}
	return result
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
