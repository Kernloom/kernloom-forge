// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kernloom/kernloom-forge/internal/api"
	"gopkg.in/yaml.v3"
)

var errNoPolicyAssignment = errors.New("no policy assignment matched node")

type assignmentManifest struct {
	APIVersion string             `yaml:"apiVersion"`
	Kind       string             `yaml:"kind"`
	Metadata   assignmentMetadata `yaml:"metadata,omitempty"`
	Spec       assignmentSpec     `yaml:"spec"`
}

type assignmentMetadata struct {
	Name string `yaml:"name,omitempty"`
}

type assignmentSpec struct {
	Assignments []nodePolicyAssignment `yaml:"assignments"`
}

type nodePolicyAssignment struct {
	ID                   string       `yaml:"id"`
	Intent               string       `yaml:"intent"`
	Target               string       `yaml:"target,omitempty"`
	NodeSelector         nodeSelector `yaml:"nodeSelector,omitempty"`
	RequiredCapabilities []string     `yaml:"requiredCapabilities,omitempty"`
}

type nodeSelector struct {
	NodeIDs      []string          `yaml:"nodeIDs,omitempty"`
	Adapters     []string          `yaml:"adapters,omitempty"`
	Capabilities []string          `yaml:"capabilities,omitempty"`
	Labels       map[string]string `yaml:"labels,omitempty"`
}

func loadAssignments(path string) (*assignmentManifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading assignments %s: %w", path, err)
	}
	var manifest assignmentManifest
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("parsing assignments %s: %w", path, err)
	}
	if manifest.Kind != "" && manifest.Kind != "NodePolicyAssignments" {
		return nil, fmt.Errorf("assignments kind must be NodePolicyAssignments, got %q", manifest.Kind)
	}
	if len(manifest.Spec.Assignments) == 0 {
		return nil, fmt.Errorf("assignments must contain at least one entry")
	}
	for i, assignment := range manifest.Spec.Assignments {
		if assignment.ID == "" {
			return nil, fmt.Errorf("assignments[%d].id is required", i)
		}
		if assignment.Intent == "" {
			return nil, fmt.Errorf("assignments[%d].intent is required", i)
		}
	}
	return &manifest, nil
}

func selectAssignment(assignments *assignmentManifest, node api.NodeRecord) (*nodePolicyAssignment, error) {
	if assignments == nil {
		return nil, fmt.Errorf("assignment manifest is required")
	}
	caps := nodeCapabilitySet(node)
	adapters := nodeAdapterSet(node)
	labels := nodeLabelMap(node)
	for i := range assignments.Spec.Assignments {
		assignment := &assignments.Spec.Assignments[i]
		if !selectorMatchesNode(assignment.NodeSelector, node.NodeID, adapters, caps, labels) {
			continue
		}
		missing := missingCapabilities(append(append([]string(nil), assignment.NodeSelector.Capabilities...), assignment.RequiredCapabilities...), caps)
		if len(missing) > 0 {
			return nil, fmt.Errorf("assignment %q matched node %q but capabilities are missing: %v", assignment.ID, node.NodeID, missing)
		}
		return assignment, nil
	}
	return nil, fmt.Errorf("%w %q", errNoPolicyAssignment, node.NodeID)
}

func selectorMatchesNode(sel nodeSelector, nodeID string, adapters map[string]bool, caps map[string]bool, labels map[string]string) bool {
	if len(sel.NodeIDs) > 0 && !stringSetContains(sel.NodeIDs, nodeID) {
		return false
	}
	for _, adapter := range sel.Adapters {
		if !adapters[adapter] {
			return false
		}
	}
	for _, cap := range sel.Capabilities {
		if !caps[cap] {
			return false
		}
	}
	for key, want := range sel.Labels {
		got, ok := labels[strings.TrimSpace(key)]
		if !ok || got != strings.TrimSpace(want) {
			return false
		}
	}
	return true
}

func nodeCapabilitySet(node api.NodeRecord) map[string]bool {
	out := make(map[string]bool, len(node.Inventory.EffectiveCapabilities))
	for _, cap := range node.Inventory.EffectiveCapabilities {
		if cap.ID != "" && cap.Status != "unavailable" {
			out[cap.ID] = true
		}
	}
	return out
}

func nodeAdapterSet(node api.NodeRecord) map[string]bool {
	out := map[string]bool{}
	if node.Inventory.ControlledBy.PluginAdapter != "" {
		addAdapterAlias(out, node.Inventory.ControlledBy.PluginAdapter)
	}
	if node.Inventory.Metadata.ID != "" {
		addAdapterAlias(out, node.Inventory.Metadata.ID)
	}
	for _, adapter := range node.ConfigReport.Adapters {
		if !adapter.Enabled {
			continue
		}
		if adapter.ID != "" {
			addAdapterAlias(out, adapter.ID)
		}
		if adapter.Plugin != "" {
			addAdapterAlias(out, adapter.Plugin)
		}
	}
	return out
}

func nodeLabelMap(node api.NodeRecord) map[string]string {
	out := make(map[string]string, len(node.Inventory.Labels))
	for key, value := range node.Inventory.Labels {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(value)
	}
	return out
}

func addAdapterAlias(out map[string]bool, adapter string) {
	adapter = strings.TrimSpace(adapter)
	if adapter == "" {
		return
	}
	out[adapter] = true
	if strings.HasPrefix(adapter, "builtin-") {
		out[strings.TrimPrefix(adapter, "builtin-")] = true
		return
	}
	out["builtin-"+adapter] = true
}

func missingCapabilities(required []string, caps map[string]bool) []string {
	var missing []string
	seen := map[string]bool{}
	for _, cap := range required {
		if cap == "" || seen[cap] {
			continue
		}
		seen[cap] = true
		if !caps[cap] {
			missing = append(missing, cap)
		}
	}
	return missing
}

func stringSetContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func resolveAssignmentIntent(baseDir string, assignment *nodePolicyAssignment) string {
	if assignment == nil || assignment.Intent == "" || filepath.IsAbs(assignment.Intent) {
		return assignment.Intent
	}
	return filepath.Join(baseDir, assignment.Intent)
}
