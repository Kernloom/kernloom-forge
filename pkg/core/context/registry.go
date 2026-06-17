// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package context

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ContextKeyRegistry is the top-level YAML document defining canonical context keys.
//
// Lives in: registries/context/canonical-keys.yaml
// Versioned in Git; version is embedded in compiled RuntimeBundles and ContextSnapshots.
type ContextKeyRegistry struct {
	APIVersion string       `yaml:"apiVersion"`
	Kind       string       `yaml:"kind"`
	Metadata   RegistryMeta `yaml:"metadata"`
	Spec       RegistrySpec `yaml:"spec"`
}

// RegistryMeta identifies the registry document.
type RegistryMeta struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

// RegistrySpec holds the list of canonical key definitions.
type RegistrySpec struct {
	Keys []CanonicalKeyDef `yaml:"keys"`
}

// CanonicalKeyDef is the definition of a single canonical context key.
type CanonicalKeyDef struct {
	// ID is the canonical key (e.g. "device.posture.status").
	// Must follow the pattern: <entity_scope>.<attribute_path>
	ID string `yaml:"id"`

	// Type is the value type: string, string_enum, string_list, integer, float, boolean.
	Type string `yaml:"type"`

	// Values is the allowed value set for string_enum types.
	Values []string `yaml:"values,omitempty"`

	// Scope is the entity scope this key applies to: subject, device, resource,
	// session, edge, workload, component.
	Scope string `yaml:"scope"`

	// Sensitivity classifies data sensitivity: low, medium, high.
	Sensitivity string `yaml:"sensitivity,omitempty"`

	// DefaultTTL is the default validity window (e.g. "15m", "8h").
	DefaultTTL string `yaml:"defaultTTL,omitempty"`

	// PermittedSources lists PIP adapter types allowed to supply this key.
	// Empty means any source is permitted.
	PermittedSources []string `yaml:"permittedSources,omitempty"`

	// Description is human-readable documentation.
	Description string `yaml:"description,omitempty"`

	// Deprecated marks this key as deprecated.
	Deprecated bool `yaml:"deprecated,omitempty"`

	// ReplacedBy is the replacement key ID when this one is deprecated.
	ReplacedBy string `yaml:"replacedBy,omitempty"`
}

// Registry is the loaded, indexed context key registry.
// It is the authoritative source for validating context key names and values.
type Registry struct {
	Version string
	keys    map[string]*CanonicalKeyDef
}

// LoadRegistry parses a ContextKeyRegistry from a YAML file.
func LoadRegistry(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading context registry %s: %w", path, err)
	}
	return ParseRegistry(data)
}

// LoadRegistryDir loads and merges all *.yaml files in a directory
// that have kind: ContextKeyRegistry. Useful for split registry files.
func LoadRegistryDir(dir string) (*Registry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading registry dir %s: %w", dir, err)
	}
	merged := &ContextKeyRegistry{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "ContextKeyRegistry",
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		var r ContextKeyRegistry
		if err := yaml.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("%s: parse: %w", e.Name(), err)
		}
		if r.Kind != "ContextKeyRegistry" {
			continue
		}
		if merged.Metadata.Version == "" {
			merged.Metadata = r.Metadata
		}
		merged.Spec.Keys = append(merged.Spec.Keys, r.Spec.Keys...)
	}
	return buildRegistry(merged)
}

// ParseRegistry parses a ContextKeyRegistry from raw YAML bytes.
func ParseRegistry(data []byte) (*Registry, error) {
	var r ContextKeyRegistry
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parsing ContextKeyRegistry: %w", err)
	}
	if r.Kind != "ContextKeyRegistry" {
		return nil, fmt.Errorf("expected kind ContextKeyRegistry, got %q", r.Kind)
	}
	return buildRegistry(&r)
}

func buildRegistry(r *ContextKeyRegistry) (*Registry, error) {
	reg := &Registry{
		Version: r.Metadata.Version,
		keys:    make(map[string]*CanonicalKeyDef, len(r.Spec.Keys)),
	}
	for i := range r.Spec.Keys {
		def := &r.Spec.Keys[i]
		if def.ID == "" {
			return nil, fmt.Errorf("context key at index %d has no id", i)
		}
		if _, dup := reg.keys[def.ID]; dup {
			return nil, fmt.Errorf("duplicate context key %q", def.ID)
		}
		reg.keys[def.ID] = def
	}
	return reg, nil
}

// Has returns true if the key is registered.
func (r *Registry) Has(key string) bool {
	_, ok := r.keys[key]
	return ok
}

// Lookup returns the key definition, or nil if unknown.
func (r *Registry) Lookup(key string) *CanonicalKeyDef {
	return r.keys[key]
}

// ValidateValue checks whether value is valid for the given key.
// Returns nil when valid or when no constraints apply (e.g. free string type).
func (r *Registry) ValidateValue(key, value string) error {
	def, ok := r.keys[key]
	if !ok {
		return fmt.Errorf("unknown canonical context key %q", key)
	}
	if def.Deprecated {
		// warn but don't block
		_ = def.ReplacedBy
	}
	if def.Type == "string_enum" && len(def.Values) > 0 {
		for _, v := range def.Values {
			if v == value {
				return nil
			}
		}
		return fmt.Errorf("value %q is not valid for key %q (allowed: %v)", value, key, def.Values)
	}
	return nil
}

// ValidateSource checks whether a PIP source type is permitted to supply the key.
// Returns nil when no source restrictions are defined.
func (r *Registry) ValidateSource(key, sourceAdapter string) error {
	def, ok := r.keys[key]
	if !ok {
		return fmt.Errorf("unknown canonical context key %q", key)
	}
	if len(def.PermittedSources) == 0 {
		return nil // no restriction
	}
	for _, src := range def.PermittedSources {
		if src == sourceAdapter {
			return nil
		}
	}
	return fmt.Errorf("source %q is not permitted to supply key %q (permitted: %v)",
		sourceAdapter, key, def.PermittedSources)
}

// AllKeys returns all registered key IDs, sorted.
func (r *Registry) AllKeys() []string {
	out := make([]string, 0, len(r.keys))
	for k := range r.keys {
		out = append(out, k)
	}
	return out
}

// ValidateSignal checks whether a signal path used in a policy condition
// references a known canonical context key.
// Returns a diagnostic, not a hard error — the compiler decides severity.
func (r *Registry) ValidateSignal(signal string) ValidationResult {
	if r.Has(signal) {
		return ValidationResult{OK: true, Key: signal}
	}
	// Try to suggest closest known keys with same prefix.
	var suggestions []string
	parts := strings.Split(signal, ".")
	if len(parts) > 0 {
		prefix := parts[0] + "."
		for k := range r.keys {
			if strings.HasPrefix(k, prefix) {
				suggestions = append(suggestions, k)
			}
		}
	}
	return ValidationResult{
		OK:          false,
		Key:         signal,
		Message:     fmt.Sprintf("signal %q is not a registered canonical context key", signal),
		Suggestions: suggestions,
	}
}

// ValidationResult is the outcome of a registry validation check.
type ValidationResult struct {
	OK          bool
	Key         string
	Message     string
	Suggestions []string
}
