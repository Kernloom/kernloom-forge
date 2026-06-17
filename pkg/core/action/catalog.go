// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package action defines the RuntimeActionCatalog — the set of TTL-bounded,
// auto-reverting actions an adapter can execute when Kernloom's Runtime PDP
// issues a restriction decision.
//
// All runtime actions must be monotonically restrictive: they may reduce
// access but must never grant additional access or widen vendor permissions.
//
// Each action declares its revert strategy and conflict policy. The Action
// Broker is responsible for lease management, fencing tokens, and ensuring
// that auto-revert only restores to the pre-action state when no conflicting
// changes have occurred in the meantime.
package action

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ActionEffect classifies the direction of an action's impact.
// All runtime actions must be restrictive — this is validated at
// catalog load time.
type ActionEffect string

const (
	// EffectRestrictive: the action can only reduce access.
	EffectRestrictive ActionEffect = "restrictive"
)

// RequirementLevel declares whether a runtime requirement is mandatory.
type RequirementLevel string

const (
	LevelRequired RequirementLevel = "required"
	LevelOptional RequirementLevel = "optional"
)

// RevertStrategyType declares how the action adapter restores previous state.
type RevertStrategyType string

const (
	// RevertRestorePreviousState: the adapter records the pre-action state and
	// restores it unconditionally on TTL expiry or explicit revert.
	RevertRestorePreviousState RevertStrategyType = "restore_previous_state"

	// RevertCompareAndRestore: the adapter records the pre-action state AND a
	// fencing token. On revert, it checks that the fencing token is still
	// current before restoring. If the state changed since the action was
	// applied (manual change, conflicting action), the revert is aborted and
	// flagged for operator review.
	RevertCompareAndRestore RevertStrategyType = "compare_and_restore"
)

// ConflictPolicyType declares what happens when multiple restrictions compete.
type ConflictPolicyType string

const (
	// ConflictStrongestRestrictionWins: the most restrictive active action
	// takes precedence. A less restrictive action does not overwrite a more
	// restrictive one still within its TTL.
	ConflictStrongestRestrictionWins ConflictPolicyType = "strongest_restriction_wins"
)

// RuntimeActionCatalog is the top-level adapter-level action catalog.
// Each action in the catalog is a reusable, parameterized restriction primitive.
//
// Example YAML:
//
//	apiVersion: kernloom.io/v1alpha1
//	kind: RuntimeActionCatalog
//	metadata:
//	  name: openziti-actions
//	  adapterRef: openziti
//	spec:
//	  actions:
//	    - id: remove_kernloom_access_attribute
//	      effect: restrictive
//	      scope: identity
//	      requirements:
//	        ttl: required
//	        lease: required
//	      revertStrategy:
//	        type: compare_and_restore
//	        requireFencingToken: true
//	      conflictPolicy:
//	        type: strongest_restriction_wins
type RuntimeActionCatalog struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	Metadata   CatalogMetadata `yaml:"metadata"`
	Spec       CatalogSpec     `yaml:"spec"`
}

// CatalogMetadata identifies the action catalog.
type CatalogMetadata struct {
	Name       string `yaml:"name"`
	AdapterRef string `yaml:"adapterRef"`
}

// CatalogSpec holds all action entries.
type CatalogSpec struct {
	Actions []ActionEntry `yaml:"actions"`
}

// ActionEntry declares one runtime action the adapter can execute.
type ActionEntry struct {
	// ID is the canonical action identifier, referenced by the mapping's
	// CompensatingBinding and the profile's allowedRuntimeActions.
	ID string `yaml:"id"`

	// Effect must be restrictive. Actions that could grant access are invalid.
	Effect ActionEffect `yaml:"effect"`

	// Scope identifies what target object the action modifies.
	// Examples: identity, role_attribute, service_policy, session.
	Scope string `yaml:"scope"`

	// Preconditions are conditions that must be true before the action
	// can be safely applied.
	Preconditions []string `yaml:"preconditions,omitempty"`

	// Parameters declares allowed configuration parameters for this action.
	// Keys are parameter names, values are descriptions or type hints.
	Parameters map[string]string `yaml:"parameters,omitempty"`

	// Requirements declares mandatory operational constraints.
	Requirements ActionRequirements `yaml:"requirements"`

	// RevertStrategy declares how the adapter restores state after TTL expiry.
	RevertStrategy RevertStrategy `yaml:"revertStrategy"`

	// ConflictPolicy declares what happens when multiple concurrent restrictions
	// target the same object.
	ConflictPolicy ConflictPolicy `yaml:"conflictPolicy"`
}

// ActionRequirements declares which operational properties are mandatory for
// this action. All fields default to "optional" if not set.
type ActionRequirements struct {
	TTL        RequirementLevel `yaml:"ttl"`
	Lease      RequirementLevel `yaml:"lease"`
	Audit      RequirementLevel `yaml:"audit"`
	AutoRevert RequirementLevel `yaml:"autoRevert"`
}

// RevertStrategy declares how the adapter restores state after TTL expiry.
type RevertStrategy struct {
	Type                RevertStrategyType `yaml:"type"`
	RequireFencingToken bool               `yaml:"requireFencingToken,omitempty"`
}

// ConflictPolicy declares conflict resolution behaviour.
type ConflictPolicy struct {
	Type ConflictPolicyType `yaml:"type"`
}

// ActionByID returns the action with the given ID, or nil.
func (c *RuntimeActionCatalog) ActionByID(id string) *ActionEntry {
	for i := range c.Spec.Actions {
		if c.Spec.Actions[i].ID == id {
			return &c.Spec.Actions[i]
		}
	}
	return nil
}

// Validate performs basic structural checks.
func (c *RuntimeActionCatalog) Validate() error {
	if c.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if c.Kind != "RuntimeActionCatalog" {
		return fmt.Errorf("kind must be RuntimeActionCatalog, got %q", c.Kind)
	}
	if c.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if c.Metadata.AdapterRef == "" {
		return fmt.Errorf("metadata.adapterRef is required")
	}
	for i, a := range c.Spec.Actions {
		if a.ID == "" {
			return fmt.Errorf("spec.actions[%d].id is required", i)
		}
		if a.Effect != EffectRestrictive {
			return fmt.Errorf("spec.actions[%d] (%s): effect must be restrictive", i, a.ID)
		}
	}
	return nil
}

// LoadFromFile parses a RuntimeActionCatalog from a YAML file.
func LoadFromFile(path string) (*RuntimeActionCatalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses a RuntimeActionCatalog from raw YAML bytes.
func Parse(data []byte) (*RuntimeActionCatalog, error) {
	var c RuntimeActionCatalog
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing RuntimeActionCatalog: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid RuntimeActionCatalog: %w", err)
	}
	return &c, nil
}
