// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package validator validates node definitions and policy files against the
// Kernloom core registry.
package validator

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kernloom/kernloom-forge/internal/registry"
)

// AdapterCapability is one capability entry in an node definition.
type AdapterCapability struct {
	ID                 string   `yaml:"id"`
	Granularity        []string `yaml:"granularity"`
	Scopes             []string `yaml:"scopes"`
	SupportsTTL        bool     `yaml:"supports_ttl"`
	SupportsDryRun     bool     `yaml:"supports_dry_run"`
	ProducesSignals    []string `yaml:"produces_signals"`
	ProducesStatistics []string `yaml:"produces_statistics"`
	SupportedSignals   []string `yaml:"supported_signals"`
	SupportedScopes    []string `yaml:"supported_scopes"`
	MapsTo             []string `yaml:"maps_to"`
	ModelTypes         []string `yaml:"model_types"`
}

// NodeDefinition is the top-level structure of an node definition file.
// Describes what a software component (adapter type) is capable of.
// Distinct from NodeManifest, which describes what a concrete deployed node instance provides.
//
// Supports apiVersion forge.kernloom.io/v1alpha1 (kind: NodeManifest, deprecated)
// and v1alpha2 (kind: NodeDefinition).
type NodeDefinition struct {
	Kind       string `yaml:"kind"`
	APIVersion string `yaml:"apiVersion"`
	Metadata   struct {
		ID      string `yaml:"id"`
		Name    string `yaml:"name"`
		Version string `yaml:"version"`
	} `yaml:"metadata"`
	Adapter struct {
		ID       string   `yaml:"id"`
		Roles    []string `yaml:"roles"`    // v1alpha2
		Types    []string `yaml:"types"`    // v1alpha1 — kept for backward compatibility
		Profiles []string `yaml:"profiles"` // v1alpha2
	} `yaml:"adapter"`
	Placement            map[string]any      `yaml:"placement"`
	Implementation       map[string]any      `yaml:"implementation"`
	Capabilities         []AdapterCapability `yaml:"capabilities"`
	OptionalCapabilities []AdapterCapability `yaml:"optional_capabilities"`
	Constraints          map[string]any      `yaml:"constraints"`
	SelectionTraits      map[string]string   `yaml:"selection_traits"`
	SignalsProduced      []string            `yaml:"signals_produced"` // v1alpha1 legacy
}

// effectiveRoles returns the adapter's roles for validation, falling back to
// the v1alpha1 "types" field when "roles" is not set.
func effectiveRoles(m *NodeDefinition) []string {
	if len(m.Adapter.Roles) > 0 {
		return m.Adapter.Roles
	}
	return m.Adapter.Types
}

// ValidateAdapterFile loads and validates a single node definition file.
func ValidateAdapterFile(path string, reg *registry.Registry) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	var m NodeDefinition
	if err := yaml.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	return ValidateAdapter(&m, reg)
}

// ValidateAdapter validates a parsed NodeDefinition against the registry.
func ValidateAdapter(m *NodeDefinition, reg *registry.Registry) error {
	if m.Metadata.ID == "" {
		return fmt.Errorf("node definition missing metadata.id")
	}

	// Accept NodeDefinition (v1alpha2); AdapterDefinition and AdapterManifest are deprecated aliases.
	validKinds := map[string]bool{
		"NodeDefinition":    true,
		"AdapterDefinition": true, // renamed → NodeDefinition
		"AdapterManifest":   true, // v1alpha1 original name
	}
	if m.Kind != "" && !validKinds[m.Kind] {
		return fmt.Errorf("node %s: unknown kind %q (expected NodeDefinition)", m.Metadata.ID, m.Kind)
	}

	roles := effectiveRoles(m)
	if len(roles) == 0 {
		return fmt.Errorf("adapter %s: no roles (or types for v1alpha1) declared", m.Metadata.ID)
	}

	// All declared roles must be known.
	for _, role := range roles {
		if !reg.HasComponentRole(role) {
			return fmt.Errorf("adapter %s: unknown role %q", m.Metadata.ID, role)
		}
	}

	// All declared profiles must exist in the registry.
	for _, profileID := range m.Adapter.Profiles {
		if !reg.HasComponentProfile(profileID) {
			return fmt.Errorf("adapter %s: unknown profile %q", m.Metadata.ID, profileID)
		}
	}

	// Validate each declared capability.
	for _, ac := range m.Capabilities {
		if err := validateAdapterCapability(m, &ac, roles, reg); err != nil {
			return err
		}
	}

	// Optional capabilities follow the same rules.
	for _, ac := range m.OptionalCapabilities {
		if err := validateAdapterCapability(m, &ac, roles, reg); err != nil {
			return err
		}
	}

	// Validate legacy top-level signals_produced.
	for _, sigID := range m.SignalsProduced {
		if strings.HasPrefix(sigID, "x.") {
			return fmt.Errorf("adapter %s: extension signal %q not allowed in strict mode", m.Metadata.ID, sigID)
		}
		if !reg.HasSignal(sigID) {
			return fmt.Errorf("adapter %s: unknown signal %q in signals_produced", m.Metadata.ID, sigID)
		}
		sig := reg.Signals[sigID]
		if len(sig.AllowedProducers) > 0 && !anyMatch(roles, sig.AllowedProducers) {
			return fmt.Errorf("adapter %s: not allowed to produce signal %q (allowed producers: %v)",
				m.Metadata.ID, sigID, sig.AllowedProducers)
		}
	}

	// Validate selection_traits.
	for traitKey, traitVal := range m.SelectionTraits {
		trait, ok := reg.SelectionTraits[traitKey]
		if !ok {
			return fmt.Errorf("adapter %s: unknown selection_trait key %q", m.Metadata.ID, traitKey)
		}
		if !contains(trait.AllowedValues, traitVal) {
			return fmt.Errorf("adapter %s: selection_trait %q has invalid value %q (allowed: %v)",
				m.Metadata.ID, traitKey, traitVal, trait.AllowedValues)
		}
	}

	return nil
}

var identifierRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.]*$`)

func validateAdapterCapability(
	m *NodeDefinition,
	ac *AdapterCapability,
	roles []string,
	reg *registry.Registry,
) error {
	if ac.ID == "" {
		return fmt.Errorf("adapter %s: capability entry missing id", m.Metadata.ID)
	}

	if strings.HasPrefix(ac.ID, "x.") {
		return fmt.Errorf("adapter %s: extension capability %q not allowed in strict mode", m.Metadata.ID, ac.ID)
	}

	cap, ok := reg.Capabilities[ac.ID]
	if !ok {
		return fmt.Errorf("adapter %s: unknown capability %q", m.Metadata.ID, ac.ID)
	}

	if !anyMatch(roles, cap.AllowedRoles) {
		return fmt.Errorf("adapter %s: capability %q not allowed for roles %v (allowed: %v)",
			m.Metadata.ID, ac.ID, roles, cap.AllowedRoles)
	}

	if len(cap.AllowedGranularities) > 0 {
		for _, g := range ac.Granularity {
			if !contains(cap.AllowedGranularities, g) {
				return fmt.Errorf("adapter %s: capability %q granularity %q not in allowed list %v",
					m.Metadata.ID, ac.ID, g, cap.AllowedGranularities)
			}
			if !reg.HasGranularity(g) {
				return fmt.Errorf("adapter %s: capability %q unknown granularity %q",
					m.Metadata.ID, ac.ID, g)
			}
		}
	}

	for _, sigID := range ac.ProducesSignals {
		if !reg.HasSignal(sigID) {
			return fmt.Errorf("adapter %s: capability %q produces unknown signal %q",
				m.Metadata.ID, ac.ID, sigID)
		}
	}

	for _, sigID := range ac.SupportedSignals {
		if !reg.HasSignal(sigID) {
			return fmt.Errorf("adapter %s: capability %q supported_signals references unknown signal %q",
				m.Metadata.ID, ac.ID, sigID)
		}
	}

	for _, statID := range ac.ProducesStatistics {
		if !reg.HasBaselineStatistic(statID) {
			return fmt.Errorf("adapter %s: capability %q produces unknown baseline_statistic %q",
				m.Metadata.ID, ac.ID, statID)
		}
	}

	for _, capID := range ac.MapsTo {
		if !reg.HasCapability(capID) {
			return fmt.Errorf("adapter %s: capability %q maps_to unknown capability %q",
				m.Metadata.ID, ac.ID, capID)
		}
	}

	return nil
}

// ParseNodeFile parses a node definition file without validating it against the registry.
func ParseNodeFile(path string) (NodeDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return NodeDefinition{}, fmt.Errorf("read %s: %w", path, err)
	}
	var m NodeDefinition
	if err := yaml.Unmarshal(data, &m); err != nil {
		return NodeDefinition{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return m, nil
}

// LoadNodeDefinitionsFromDir loads and validates all *.yaml node definition files
// from dir. Files that fail validation are returned as an error immediately.
func LoadNodeDefinitionsFromDir(dir string, reg *registry.Registry) ([]NodeDefinition, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", dir, err)
	}
	var nodes []NodeDefinition
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		m, err := ParseNodeFile(path)
		if err != nil {
			return nil, err
		}
		if err := ValidateAdapter(&m, reg); err != nil {
			return nil, fmt.Errorf("invalid node %s: %w", e.Name(), err)
		}
		nodes = append(nodes, m)
	}
	return nodes, nil
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func anyMatch(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}
