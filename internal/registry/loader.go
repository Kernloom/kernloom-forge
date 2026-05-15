// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// raw envelope types for YAML unmarshalling.

type rawIntents struct {
	Intents []Intent `yaml:"intents"`
}

type rawCapabilities struct {
	Capabilities []Capability `yaml:"capabilities"`
}

type rawSignals struct {
	Signals []Signal `yaml:"signals"`
}

type rawGranularities struct {
	Granularities []Granularity `yaml:"granularities"`
}

type rawScopes struct {
	Scopes []Scope `yaml:"scopes"`
}

type rawAdapterTypes struct {
	AdapterTypes []AdapterType `yaml:"adapter_types"`
}

type rawCompilerRules struct {
	CompilerRules []CompilerRule `yaml:"compiler_rules"`
}

// LoadDir loads all registry files from dir and returns a validated Registry.
// Each file must be named after its type (intents.yaml, capabilities.yaml, etc.).
func LoadDir(dir string) (*Registry, error) {
	r := &Registry{
		Intents:       make(map[string]*Intent),
		Capabilities:  make(map[string]*Capability),
		Signals:       make(map[string]*Signal),
		Granularities: make(map[string]*Granularity),
		Scopes:        make(map[string]*Scope),
		AdapterTypes:  make(map[string]*AdapterType),
		CompilerRules: make(map[string]*CompilerRule),
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read registry dir %s: %w", dir, err)
	}

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, f.Name())
		if err := r.loadFile(path); err != nil {
			return nil, fmt.Errorf("load %s: %w", f.Name(), err)
		}
	}

	return r, r.validate()
}

func (r *Registry) loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	base := filepath.Base(path)
	switch base {
	case "intents.yaml":
		var v rawIntents
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.Intents {
			item := &v.Intents[i]
			if item.ID == "" {
				return fmt.Errorf("intent missing id")
			}
			if _, dup := r.Intents[item.ID]; dup {
				return fmt.Errorf("duplicate intent id: %s", item.ID)
			}
			r.Intents[item.ID] = item
		}

	case "capabilities.yaml":
		var v rawCapabilities
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.Capabilities {
			item := &v.Capabilities[i]
			if item.ID == "" {
				return fmt.Errorf("capability missing id")
			}
			if _, dup := r.Capabilities[item.ID]; dup {
				return fmt.Errorf("duplicate capability id: %s", item.ID)
			}
			r.Capabilities[item.ID] = item
		}

	case "signals.yaml":
		var v rawSignals
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.Signals {
			item := &v.Signals[i]
			if item.ID == "" {
				return fmt.Errorf("signal missing id")
			}
			if _, dup := r.Signals[item.ID]; dup {
				return fmt.Errorf("duplicate signal id: %s", item.ID)
			}
			r.Signals[item.ID] = item
		}

	case "granularities.yaml":
		var v rawGranularities
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.Granularities {
			item := &v.Granularities[i]
			if item.ID == "" {
				return fmt.Errorf("granularity missing id")
			}
			if _, dup := r.Granularities[item.ID]; dup {
				return fmt.Errorf("duplicate granularity id: %s", item.ID)
			}
			r.Granularities[item.ID] = item
		}

	case "scopes.yaml":
		var v rawScopes
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.Scopes {
			item := &v.Scopes[i]
			if item.ID == "" {
				return fmt.Errorf("scope missing id")
			}
			if _, dup := r.Scopes[item.ID]; dup {
				return fmt.Errorf("duplicate scope id: %s", item.ID)
			}
			r.Scopes[item.ID] = item
		}

	case "adapter_types.yaml":
		var v rawAdapterTypes
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.AdapterTypes {
			item := &v.AdapterTypes[i]
			if item.ID == "" {
				return fmt.Errorf("adapter_type missing id")
			}
			if _, dup := r.AdapterTypes[item.ID]; dup {
				return fmt.Errorf("duplicate adapter_type id: %s", item.ID)
			}
			r.AdapterTypes[item.ID] = item
		}

	case "compiler_rules.yaml":
		var v rawCompilerRules
		if err := yaml.Unmarshal(data, &v); err != nil {
			return err
		}
		for i := range v.CompilerRules {
			item := &v.CompilerRules[i]
			if item.ID == "" {
				return fmt.Errorf("compiler_rule missing id")
			}
			if _, dup := r.CompilerRules[item.ID]; dup {
				return fmt.Errorf("duplicate compiler_rule id: %s", item.ID)
			}
			r.CompilerRules[item.ID] = item
		}
	}
	return nil
}

// validate performs cross-reference checks after all files are loaded.
func (r *Registry) validate() error {
	// Every capability referenced by an intent's compiles_to must exist.
	for _, intent := range r.Intents {
		for _, capID := range intent.CompilesTo {
			if !r.HasCapability(capID) {
				return fmt.Errorf("intent %s: compiles_to references unknown capability %q", intent.ID, capID)
			}
		}
	}

	// Every capability's allowed_adapter_types must be known.
	for _, cap := range r.Capabilities {
		for _, at := range cap.AllowedAdapterTypes {
			if !r.HasAdapterType(at) {
				return fmt.Errorf("capability %s: unknown adapter_type %q", cap.ID, at)
			}
		}
		for _, g := range cap.AllowedGranularities {
			if !r.HasGranularity(g) {
				return fmt.Errorf("capability %s: unknown granularity %q", cap.ID, g)
			}
		}
		for _, sig := range cap.ProducesSignals {
			if !r.HasSignal(sig) {
				return fmt.Errorf("capability %s: produces unknown signal %q", cap.ID, sig)
			}
		}
	}

	// Every signal's allowed_scopes must be known.
	for _, sig := range r.Signals {
		for _, sc := range sig.AllowedScopes {
			if !r.HasScope(sc) {
				return fmt.Errorf("signal %s: unknown scope %q", sig.ID, sc)
			}
		}
		for _, at := range sig.AllowedProducers {
			if !r.HasAdapterType(at) {
				return fmt.Errorf("signal %s: unknown producer adapter_type %q", sig.ID, at)
			}
		}
	}

	// Every compiler rule must reference a known intent and known capabilities.
	for _, rule := range r.CompilerRules {
		if !r.HasIntent(rule.Intent) {
			return fmt.Errorf("compiler_rule %s: unknown intent %q", rule.ID, rule.Intent)
		}
		for _, t := range rule.Targets {
			if !r.HasCapability(t.Capability) {
				return fmt.Errorf("compiler_rule %s: unknown capability %q", rule.ID, t.Capability)
			}
			for _, g := range t.RequiredGranularity {
				if !r.HasGranularity(g) {
					return fmt.Errorf("compiler_rule %s: unknown granularity %q", rule.ID, g)
				}
			}
		}
	}

	return nil
}
