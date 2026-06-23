// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package intent

import (
	"fmt"
	"os"

	contracts "github.com/kernloom/kernloom-contracts"
	"gopkg.in/yaml.v3"
)

// PolicyIntent is a thin composition manifest. It groups canonical policy
// documents under one operator intent without becoming a second policy engine.
type PolicyIntent struct {
	APIVersion string           `yaml:"apiVersion"`
	Kind       PolicyKind       `yaml:"kind"`
	Metadata   PolicyMetadata   `yaml:"metadata"`
	Spec       PolicyIntentSpec `yaml:"spec"`
}

type PolicyIntentSpec struct {
	Description string                    `yaml:"description,omitempty"`
	Protect     PolicyIntentProtect       `yaml:"protect,omitempty"`
	Documents   PolicyIntentDocumentSet   `yaml:"documents"`
	Registries  PolicyIntentRegistryPins  `yaml:"registries,omitempty"`
	Runtime     PolicyIntentRuntime       `yaml:"runtime,omitempty"`
	Compile     PolicyIntentCompileTarget `yaml:"compile,omitempty"`
}

type PolicyIntentRuntime struct {
	AutonomyLifecycle *contracts.RuntimeAutonomyLifecycleSpec `yaml:"autonomyLifecycle,omitempty"`
}

func (r PolicyIntentRuntime) IsZero() bool {
	return r.AutonomyLifecycle == nil
}

type PolicyIntentProtect struct {
	Resource    string `yaml:"resource,omitempty"`
	Environment string `yaml:"environment,omitempty"`
	Criticality string `yaml:"criticality,omitempty"`
}

type PolicyIntentCompileTarget struct {
	Target string `yaml:"target,omitempty"`
	Mode   string `yaml:"mode,omitempty"`
}

type PolicyIntentRegistryPins struct {
	Context                 PolicyIntentRegistryPin `yaml:"context,omitempty"`
	Actions                 PolicyIntentRegistryPin `yaml:"actions,omitempty"`
	Capabilities            PolicyIntentRegistryPin `yaml:"capabilities,omitempty"`
	Granularity             PolicyIntentRegistryPin `yaml:"granularity,omitempty"`
	DetectionEvaluators     PolicyIntentRegistryPin `yaml:"detectionEvaluators,omitempty"`
	MissingContextBehaviors PolicyIntentRegistryPin `yaml:"missingContextBehaviors,omitempty"`
	Guardrails              PolicyIntentRegistryPin `yaml:"guardrails,omitempty"`
	GapHandling             PolicyIntentRegistryPin `yaml:"gapHandling,omitempty"`
	Notifications           PolicyIntentRegistryPin `yaml:"notifications,omitempty"`
	Snapshot                PolicyIntentRegistryPin `yaml:"snapshot,omitempty"`
}

type PolicyIntentRegistryPin struct {
	Name    string `yaml:"name,omitempty"`
	Version string `yaml:"version,omitempty"`
	Digest  string `yaml:"digest,omitempty"`
}

type PolicyIntentDocumentSet struct {
	Access                 []PolicyIntentDocumentRef `yaml:"access,omitempty"`
	Requirements           []PolicyIntentDocumentRef `yaml:"requirements,omitempty"`
	Detections             []PolicyIntentDocumentRef `yaml:"detections,omitempty"`
	Responses              []PolicyIntentDocumentRef `yaml:"responses,omitempty"`
	AlertRoutes            []PolicyIntentDocumentRef `yaml:"alertRoutes,omitempty"`
	Guardrails             []PolicyIntentDocumentRef `yaml:"guardrails,omitempty"`
	CapabilityRequirements []PolicyIntentDocumentRef `yaml:"capabilityRequirements,omitempty"`
}

type PolicyIntentDocumentRef struct {
	ID      string     `yaml:"id,omitempty"`
	Kind    PolicyKind `yaml:"kind,omitempty"`
	Name    string     `yaml:"name,omitempty"`
	Version string     `yaml:"version,omitempty"`
	Ref     string     `yaml:"ref,omitempty"`
	File    string     `yaml:"file,omitempty"`
	Digest  string     `yaml:"digest,omitempty"`
}

func LoadPolicyIntentFromFile(path string) (*PolicyIntent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var p PolicyIntent
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing PolicyIntent %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid PolicyIntent %s: %w", path, err)
	}
	return &p, nil
}

func (p *PolicyIntent) Validate() error {
	if p.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if p.Kind != KindPolicyIntent {
		return fmt.Errorf("kind must be %s, got %q", KindPolicyIntent, p.Kind)
	}
	if p.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if p.Spec.Documents.count() == 0 {
		return fmt.Errorf("spec.documents must reference at least one canonical policy document")
	}
	for section, refs := range p.Spec.Documents.bySection() {
		for i, ref := range refs {
			if ref.Path() == "" {
				return fmt.Errorf("spec.documents.%s[%d] requires ref or file", section, i)
			}
			if ref.Digest != "" && !validDigestRef(ref.Digest) {
				return fmt.Errorf("spec.documents.%s[%d] digest must be sha256:<hex>", section, i)
			}
		}
	}
	for name, pin := range p.Spec.Registries.byName() {
		if pin.Digest != "" && !validDigestRef(pin.Digest) {
			return fmt.Errorf("spec.registries.%s.digest must be sha256:<hex>", name)
		}
	}
	return nil
}

func (r PolicyIntentDocumentRef) Path() string {
	if r.File != "" {
		return r.File
	}
	return r.Ref
}

func (d PolicyIntentDocumentSet) bySection() map[string][]PolicyIntentDocumentRef {
	return map[string][]PolicyIntentDocumentRef{
		"access":                 d.Access,
		"requirements":           d.Requirements,
		"detections":             d.Detections,
		"responses":              d.Responses,
		"alertRoutes":            d.AlertRoutes,
		"guardrails":             d.Guardrails,
		"capabilityRequirements": d.CapabilityRequirements,
	}
}

func (d PolicyIntentDocumentSet) count() int {
	n := 0
	for _, refs := range d.bySection() {
		n += len(refs)
	}
	return n
}

func (p PolicyIntentRegistryPins) byName() map[string]PolicyIntentRegistryPin {
	return map[string]PolicyIntentRegistryPin{
		"context":                 p.Context,
		"actions":                 p.Actions,
		"capabilities":            p.Capabilities,
		"granularity":             p.Granularity,
		"detectionEvaluators":     p.DetectionEvaluators,
		"missingContextBehaviors": p.MissingContextBehaviors,
		"guardrails":              p.Guardrails,
		"gapHandling":             p.GapHandling,
		"notifications":           p.Notifications,
		"snapshot":                p.Snapshot,
	}
}

func (p PolicyIntentRegistryPins) ByName() map[string]PolicyIntentRegistryPin {
	return p.byName()
}

func validDigestRef(digest string) bool {
	const prefix = "sha256:"
	if len(digest) != len(prefix)+64 || digest[:len(prefix)] != prefix {
		return false
	}
	for _, r := range digest[len(prefix):] {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
