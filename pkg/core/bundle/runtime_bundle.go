// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// RuntimeBundle is the signed container that Forge publishes for a KLIQ node.
//
// KLIQ's atomic activation steps (per spec doc 04):
//  1. Download to staging
//  2. Verify schema and Ed25519 signature
//  3. Verify generation > last-known-good generation (monotonic)
//  4. Verify expiry has not passed
//  5. Verify all required capabilities are available on this node
//  6. Dry-compile local CEL evaluators from PolicyPack
//  7. Atomically activate (swap staging → active)
//  8. Preserve previous bundle as last-known-good
//  9. Acknowledge activation result to Forge
type RuntimeBundle struct {
	APIVersion string        `yaml:"apiVersion" json:"apiVersion"`
	Kind       string        `yaml:"kind"       json:"kind"`
	Metadata   BundleMeta    `yaml:"metadata"   json:"metadata"`
	Spec       BundleSpec    `yaml:"spec"       json:"spec"`
	// Signature is the Ed25519 signature over the canonical BundleSpec JSON.
	// Populated by Sign(); verified by KLIQ before activation.
	Signature string `yaml:"signature,omitempty" json:"signature,omitempty"`
}

// BundleMeta identifies the bundle and controls KLIQ's activation logic.
type BundleMeta struct {
	// BundleID is a unique identifier for this bundle (UUIDv4).
	BundleID string `yaml:"bundleId" json:"bundleId"`

	// NodeID scopes this bundle to a specific KLIQ node.
	NodeID string `yaml:"nodeId" json:"nodeId"`

	// TenantID scopes the bundle to a tenant.
	TenantID string `yaml:"tenantId,omitempty" json:"tenantId,omitempty"`

	// Generation is a monotonically increasing counter.
	// KLIQ rejects any bundle whose generation <= the currently active generation.
	Generation int64 `yaml:"generation" json:"generation"`

	// IssuedAt is when Forge produced this bundle.
	IssuedAt time.Time `yaml:"issuedAt" json:"issuedAt"`

	// ExpiresAt is when KLIQ must stop using this bundle.
	// After expiry, KLIQ falls back to OfflineBehavior.
	ExpiresAt time.Time `yaml:"expiresAt" json:"expiresAt"`

	// SpecHash is the SHA-256 of the canonical BundleSpec JSON.
	// Used to verify integrity independently of the signature.
	SpecHash string `yaml:"specHash" json:"specHash"`
}

// BundleSpec is the normative content of a RuntimeBundle.
// The Ed25519 signature is computed over the canonical JSON of BundleSpec.
type BundleSpec struct {
	// PolicyPack is the compiled runtime policy KLIQ evaluates locally.
	PolicyPack RuntimePolicyPack `yaml:"policyPack" json:"policyPack"`

	// PDPProfile declares the bounds of KLIQ's local autonomy.
	PDPProfile RuntimePDPProfile `yaml:"pdpProfile" json:"pdpProfile"`

	// ContextRegistryVersion pins the canonical key registry version.
	ContextRegistryVersion string `yaml:"contextRegistryVersion" json:"contextRegistryVersion"`

	// ActiveAdapters lists the adapter IDs KLIQ should activate.
	// KLIQ must have all listed adapters available or refuse activation.
	ActiveAdapters []string `yaml:"activeAdapters,omitempty" json:"activeAdapters,omitempty"`

	// BaselineLifecycle declares the permitted baseline learning configuration.
	BaselineLifecycle BaselineLifecycleConfig `yaml:"baselineLifecycle,omitempty" json:"baselineLifecycle,omitempty"`

	// GraphLifecycle declares the permitted graph learning configuration.
	GraphLifecycle GraphLifecycleConfig `yaml:"graphLifecycle,omitempty" json:"graphLifecycle,omitempty"`
}

// BaselineLifecycleConfig controls what KLIQ's baseline engine may do.
type BaselineLifecycleConfig struct {
	// Enabled: when false, baseline learning is disabled for this node.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// MinLearningDuration is the minimum time before a baseline is considered active.
	MinLearningDuration time.Duration `yaml:"minLearningDuration,omitempty" json:"minLearningDuration,omitempty"`

	// FreezeOnHighRisk: when true, baseline updates are paused during high-risk periods.
	FreezeOnHighRisk bool `yaml:"freezeOnHighRisk" json:"freezeOnHighRisk"`
}

// GraphLifecycleConfig controls what KLIQ's graph learner may do.
type GraphLifecycleConfig struct {
	// Enabled: when false, graph learning is disabled for this node.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// MaxEdgesPerNode caps cardinality.
	MaxEdgesPerNode int `yaml:"maxEdgesPerNode,omitempty" json:"maxEdgesPerNode,omitempty"`

	// FreezeOnHighRisk: when true, no new edges are learned during high-risk periods.
	FreezeOnHighRisk bool `yaml:"freezeOnHighRisk" json:"freezeOnHighRisk"`
}

// CanonicalJSON returns the deterministic JSON serialisation of the BundleSpec
// that is signed and verified. Field order is stable (Go's encoding/json sorts
// struct fields by declaration order).
func (b *RuntimeBundle) CanonicalJSON() ([]byte, error) {
	return json.Marshal(b.Spec)
}

// ComputeHash returns the SHA-256 hex hash of the canonical BundleSpec JSON.
func (b *RuntimeBundle) ComputeHash() (string, error) {
	data, err := b.CanonicalJSON()
	if err != nil {
		return "", fmt.Errorf("bundle: computing hash: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Validate performs structural checks before signing or activation.
func (b *RuntimeBundle) Validate() error {
	if b.APIVersion == "" {
		return fmt.Errorf("bundle: apiVersion is required")
	}
	if b.Kind != "RuntimeBundle" {
		return fmt.Errorf("bundle: kind must be RuntimeBundle, got %q", b.Kind)
	}
	if b.Metadata.BundleID == "" {
		return fmt.Errorf("bundle: metadata.bundleId is required")
	}
	if b.Metadata.NodeID == "" {
		return fmt.Errorf("bundle: metadata.nodeId is required")
	}
	if b.Metadata.Generation <= 0 {
		return fmt.Errorf("bundle: metadata.generation must be > 0")
	}
	if b.Metadata.ExpiresAt.IsZero() {
		return fmt.Errorf("bundle: metadata.expiresAt is required")
	}
	if b.Metadata.IssuedAt.IsZero() {
		return fmt.Errorf("bundle: metadata.issuedAt is required")
	}
	if b.Metadata.ExpiresAt.Before(b.Metadata.IssuedAt) {
		return fmt.Errorf("bundle: expiresAt must be after issuedAt")
	}
	if b.Spec.PolicyPack.Kind != "RuntimePolicyPack" {
		return fmt.Errorf("bundle: spec.policyPack.kind must be RuntimePolicyPack")
	}
	if b.Spec.PDPProfile.Kind != "RuntimePDPProfile" {
		return fmt.Errorf("bundle: spec.pdpProfile.kind must be RuntimePDPProfile")
	}
	return nil
}
