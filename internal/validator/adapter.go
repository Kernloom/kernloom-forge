// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package validator validates adapter manifests and policy files against the
// Kernloom core registry.
package validator

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kernloom/kernloom-forge/internal/registry"
)

// AdapterCapability is one capability entry in an adapter manifest.
type AdapterCapability struct {
	ID          string   `yaml:"id"`
	Granularity []string `yaml:"granularity"`
	Scopes      []string `yaml:"scopes"`
	SupportsTTL bool     `yaml:"supports_ttl"`
}

// AdapterManifest is the top-level structure of an adapter manifest file.
type AdapterManifest struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		ID      string `yaml:"id"`
		Version string `yaml:"version"`
	} `yaml:"metadata"`
	Adapter struct {
		ID    string   `yaml:"id"`
		Types []string `yaml:"types"`
	} `yaml:"adapter"`
	Capabilities    []AdapterCapability `yaml:"capabilities"`
	SignalsProduced []string            `yaml:"signals_produced"`
}

// ValidateAdapterFile loads and validates a single adapter manifest file.
func ValidateAdapterFile(path string, reg *registry.Registry) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	var m AdapterManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	return ValidateAdapter(&m, reg)
}

// ValidateAdapter validates a parsed AdapterManifest against the registry.
func ValidateAdapter(m *AdapterManifest, reg *registry.Registry) error {
	if m.Metadata.ID == "" {
		return fmt.Errorf("adapter manifest missing metadata.id")
	}
	if len(m.Adapter.Types) == 0 {
		return fmt.Errorf("adapter %s: no adapter types declared", m.Metadata.ID)
	}

	// All declared types must be known.
	for _, t := range m.Adapter.Types {
		if !reg.HasAdapterType(t) {
			return fmt.Errorf("adapter %s: unknown adapter type %q", m.Metadata.ID, t)
		}
	}

	// Validate each declared capability.
	for _, ac := range m.Capabilities {
		if ac.ID == "" {
			return fmt.Errorf("adapter %s: capability entry missing id", m.Metadata.ID)
		}

		// Extensions (x.*) are allowed but not validated against core registry in strict mode
		// only if explicitly enabled — reject them by default.
		if strings.HasPrefix(ac.ID, "x.") {
			return fmt.Errorf("adapter %s: extension capability %q not allowed in strict mode", m.Metadata.ID, ac.ID)
		}

		cap, ok := reg.Capabilities[ac.ID]
		if !ok {
			return fmt.Errorf("adapter %s: unknown capability %q", m.Metadata.ID, ac.ID)
		}

		// The capability's allowed_adapter_types must include at least one of
		// the adapter's declared types.
		if !anyMatch(m.Adapter.Types, cap.AllowedAdapterTypes) {
			return fmt.Errorf("adapter %s: capability %q not allowed for adapter types %v (allowed: %v)",
				m.Metadata.ID, ac.ID, m.Adapter.Types, cap.AllowedAdapterTypes)
		}

		// Granularities declared by the adapter must be a subset of the
		// capability's allowed granularities (if the capability has restrictions).
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
	}

	// All declared produced signals must be known.
	for _, sigID := range m.SignalsProduced {
		if strings.HasPrefix(sigID, "x.") {
			return fmt.Errorf("adapter %s: extension signal %q not allowed in strict mode", m.Metadata.ID, sigID)
		}
		if !reg.HasSignal(sigID) {
			return fmt.Errorf("adapter %s: unknown signal %q in signals_produced", m.Metadata.ID, sigID)
		}
		// Verify the adapter's type is an allowed producer for this signal.
		sig := reg.Signals[sigID]
		if len(sig.AllowedProducers) > 0 && !anyMatch(m.Adapter.Types, sig.AllowedProducers) {
			return fmt.Errorf("adapter %s: not allowed to produce signal %q (allowed producers: %v)",
				m.Metadata.ID, sigID, sig.AllowedProducers)
		}
	}

	return nil
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
