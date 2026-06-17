// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package intent defines vendor-neutral enterprise policy documents.
//
// Every Kernloom policy document shares a common envelope:
//
//	apiVersion: kernloom.io/v1
//	kind:       <PolicyKind>
//	metadata:   ...
//	spec:       ...  ← structure depends on kind
//
// The Kind field determines which concrete type the spec belongs to.
// Callers that receive an unknown file use PeekKind to dispatch to the
// correct typed parser without parsing the full document twice.
//
// Current kinds:
//   - AccessPolicy  — who may access what under which conditions
//
// Planned kinds (not yet implemented):
//   - NetworkPolicy    — traffic rules between services/segments
//   - AdmissionPolicy  — workload/container admission rules
//   - DataPolicy       — data access and classification rules
//   - PosturePolicy    — device/endpoint compliance expectations
//   - ChangePolicy     — who may change what configuration
package intent

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// PolicyKind is the set of valid kind values for Kernloom policy documents.
type PolicyKind = string

const (
	KindAccessPolicy    PolicyKind = "AccessPolicy"
	KindNetworkPolicy   PolicyKind = "NetworkPolicy"   // planned
	KindAdmissionPolicy PolicyKind = "AdmissionPolicy" // planned
	KindDataPolicy      PolicyKind = "DataPolicy"      // planned
	KindPosturePolicy   PolicyKind = "PosturePolicy"   // planned
	KindChangePolicy    PolicyKind = "ChangePolicy"    // planned
)

// PolicyMetadata holds the identity and governance fields shared by every
// Kernloom policy document.
type PolicyMetadata struct {
	Name        string            `yaml:"name"`
	Owner       string            `yaml:"owner,omitempty"`
	Environment string            `yaml:"environment,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
}

// PolicyEnvelope is a partial parse of any Kernloom policy document that
// reads only the shared header fields. Use it to dispatch on Kind before
// doing a full typed unmarshal.
//
// Example:
//
//	env, err := PeekEnvelope(data)
//	switch env.Kind {
//	case intent.KindAccessPolicy:
//	    p, err := intent.ParseAccessPolicy(data)
//	}
type PolicyEnvelope struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       PolicyKind     `yaml:"kind"`
	Metadata   PolicyMetadata `yaml:"metadata"`
}

// PeekEnvelope reads the shared header of a Kernloom policy YAML without
// fully parsing the spec. Use this to determine the Kind before dispatching
// to a typed parser.
func PeekEnvelope(data []byte) (*PolicyEnvelope, error) {
	var env PolicyEnvelope
	if err := yaml.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("peeking policy envelope: %w", err)
	}
	if env.Kind == "" {
		return nil, fmt.Errorf("policy document has no kind field")
	}
	if env.APIVersion == "" {
		return nil, fmt.Errorf("policy document has no apiVersion field")
	}
	return &env, nil
}

// LoadEnvelopeFromFile reads the shared header from a policy YAML file on disk.
func LoadEnvelopeFromFile(path string) (*PolicyEnvelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return PeekEnvelope(data)
}
