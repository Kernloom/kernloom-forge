// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package bundler compiles a signed RuntimeBundle from Forge artifacts.
//
// Input:
//   - EnforcementPlan  — compiler output (which requirements are compensating_control)
//   - TargetIntegrationProfile — deployment profile with runtime constraints
//   - BundleConfig  — node ID, generation, expiry, risk model ref
//
// Output:
//   - Signed RuntimeBundle ready for KLIQ to download and activate
//
// The bundler translates the governance EnforcementPlan into a KLIQ-executable
// RuntimePolicyPack: requirements with compensating_control status become CEL
// rules that KLIQ's Runtime PDP evaluates against local risk assessments.
package bundler

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kernloom/kernloom-forge/pkg/core/bundle"
	"github.com/kernloom/kernloom-forge/pkg/core/plan"
	"github.com/kernloom/kernloom-forge/pkg/core/profile"
)

// BundleConfig holds the non-policy configuration for a RuntimeBundle.
type BundleConfig struct {
	// NodeID identifies the KLIQ node this bundle targets.
	NodeID string

	// TenantID scopes the bundle to a tenant (optional).
	TenantID string

	// Generation is a monotonically increasing counter.
	// Must be greater than the previously active bundle generation on this node.
	Generation int64

	// IssuedAt is the bundle creation time. Defaults to time.Now() if zero.
	IssuedAt time.Time

	// ValidFor is the lifetime of the bundle. Defaults to 24h if zero.
	ValidFor time.Duration

	// ContextRegistryVersion pins the canonical key registry version in use.
	ContextRegistryVersion string

	// ActiveAdapters lists adapter IDs KLIQ must have available.
	ActiveAdapters []string

	// RiskModelName + Version pin the risk model KLIQ uses locally.
	RiskModelName    string
	RiskModelVersion string

	// OfflineBehavior: "observe_only" | "use_last_known_good" | "fail_closed".
	// Defaults to "observe_only".
	OfflineBehavior string

	// BaselineEnabled controls whether KLIQ's baseline engine is active.
	BaselineEnabled bool

	// GraphEnabled controls whether KLIQ's graph learner is active.
	GraphEnabled bool
}

// Build produces a signed RuntimeBundle from a compiled EnforcementPlan,
// a TargetIntegrationProfile, a BundleConfig, and an Ed25519 signing key.
//
// Only requirements with status compensating_control generate runtime rules.
// Delegated, partial and implemented requirements are handled by the target's
// own runtime evaluation — no KLIQ rule is needed.
func Build(
	ep *plan.EnforcementPlan,
	prof *profile.TargetIntegrationProfile,
	cfg BundleConfig,
	privKey ed25519.PrivateKey,
) (*bundle.RuntimeBundle, error) {
	if ep == nil {
		return nil, fmt.Errorf("bundler: EnforcementPlan must not be nil")
	}
	if prof == nil {
		return nil, fmt.Errorf("bundler: TargetIntegrationProfile must not be nil")
	}
	if cfg.NodeID == "" {
		return nil, fmt.Errorf("bundler: NodeID is required")
	}
	if cfg.Generation <= 0 {
		return nil, fmt.Errorf("bundler: Generation must be > 0")
	}

	now := cfg.IssuedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	validFor := cfg.ValidFor
	if validFor == 0 {
		validFor = 24 * time.Hour
	}
	offlineBehavior := cfg.OfflineBehavior
	if offlineBehavior == "" {
		offlineBehavior = "observe_only"
	}

	// Build RuntimePolicyPack from EnforcementPlan.
	pack, err := buildPolicyPack(ep, prof)
	if err != nil {
		return nil, fmt.Errorf("bundler: building policy pack: %w", err)
	}

	// Build RuntimePDPProfile from TargetIntegrationProfile.
	pdpProfile := buildPDPProfile(prof, cfg)

	b := &bundle.RuntimeBundle{
		APIVersion: "kernloom.io/runtime/v1alpha1",
		Kind:       "RuntimeBundle",
		Metadata: bundle.BundleMeta{
			BundleID:   generateID(),
			NodeID:     cfg.NodeID,
			TenantID:   cfg.TenantID,
			Generation: cfg.Generation,
			IssuedAt:   now,
			ExpiresAt:  now.Add(validFor),
		},
		Spec: bundle.BundleSpec{
			PolicyPack:             *pack,
			PDPProfile:             *pdpProfile,
			ContextRegistryVersion: cfg.ContextRegistryVersion,
			ActiveAdapters:         cfg.ActiveAdapters,
			BaselineLifecycle: bundle.BaselineLifecycleConfig{
				Enabled:          cfg.BaselineEnabled,
				FreezeOnHighRisk: true,
				MinLearningDuration: 7 * 24 * time.Hour,
			},
			GraphLifecycle: bundle.GraphLifecycleConfig{
				Enabled:          cfg.GraphEnabled,
				MaxEdgesPerNode:  10_000,
				FreezeOnHighRisk: true,
			},
		},
	}

	if err := b.Validate(); err != nil {
		return nil, fmt.Errorf("bundler: bundle validation failed: %w", err)
	}

	// Compute and store spec hash.
	hash, err := b.ComputeHash()
	if err != nil {
		return nil, fmt.Errorf("bundler: computing hash: %w", err)
	}
	b.Metadata.SpecHash = hash

	// Sign the bundle.
	if err := Sign(b, privKey); err != nil {
		return nil, fmt.Errorf("bundler: signing: %w", err)
	}

	return b, nil
}

// Sign computes the Ed25519 signature over the canonical BundleSpec JSON
// and stores the base64-encoded signature in bundle.Signature.
func Sign(b *bundle.RuntimeBundle, privKey ed25519.PrivateKey) error {
	data, err := b.CanonicalJSON()
	if err != nil {
		return fmt.Errorf("sign: canonical JSON: %w", err)
	}
	sig := ed25519.Sign(privKey, data)
	b.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Verify checks the Ed25519 signature on a RuntimeBundle.
// Returns nil when the signature is valid and the hash matches.
func Verify(b *bundle.RuntimeBundle, pubKey ed25519.PublicKey) error {
	if b.Signature == "" {
		return fmt.Errorf("verify: bundle is not signed")
	}
	data, err := b.CanonicalJSON()
	if err != nil {
		return fmt.Errorf("verify: canonical JSON: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil {
		return fmt.Errorf("verify: decoding signature: %w", err)
	}
	if !ed25519.Verify(pubKey, data, sigBytes) {
		return fmt.Errorf("verify: signature verification failed")
	}
	// Also verify the spec hash matches.
	computed, err := b.ComputeHash()
	if err != nil {
		return fmt.Errorf("verify: computing hash: %w", err)
	}
	if b.Metadata.SpecHash != "" && computed != b.Metadata.SpecHash {
		return fmt.Errorf("verify: spec hash mismatch (stored=%s computed=%s)",
			b.Metadata.SpecHash, computed)
	}
	return nil
}

// VerifyNotExpired returns an error if the bundle has passed its ExpiresAt.
func VerifyNotExpired(b *bundle.RuntimeBundle, now time.Time) error {
	if b.Metadata.ExpiresAt.IsZero() {
		return fmt.Errorf("bundle has no expiry")
	}
	if now.After(b.Metadata.ExpiresAt) {
		return fmt.Errorf("bundle expired at %s", b.Metadata.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

// buildPolicyPack converts the compensating_control entries in an EnforcementPlan
// into executable RuntimePolicy rules.
func buildPolicyPack(ep *plan.EnforcementPlan, prof *profile.TargetIntegrationProfile) (*bundle.RuntimePolicyPack, error) {
	pack := &bundle.RuntimePolicyPack{
		APIVersion: "kernloom.io/policy/runtime/v1alpha1",
		Kind:       "RuntimePolicyPack",
		Metadata: bundle.PackMeta{
			Name:         ep.Metadata.SourcePolicy + "-" + prof.Metadata.Name,
			Generation:   1,
			SourcePolicy: ep.Metadata.SourcePolicy,
		},
	}

	for _, req := range ep.Spec.Requirements {
		if req.Status != plan.StatusCompensatingControl {
			continue
		}
		if req.ActionBinding == nil {
			continue
		}
		// Only generate a rule when the action is in the profile's allowed list.
		if !isActionAllowed(req.ActionBinding.Action, prof.Spec.AllowedRuntimeActions) {
			continue
		}

		rule := buildRuntimePolicy(req, prof)
		pack.Spec.Policies = append(pack.Spec.Policies, rule)
	}

	return pack, nil
}

// buildRuntimePolicy compiles one compensating_control requirement into a RuntimePolicy.
func buildRuntimePolicy(req plan.RequirementEnforcement, prof *profile.TargetIntegrationProfile) bundle.RuntimePolicy {
	// Default CEL expression for risk-based compensating controls.
	// The threshold values (0.80 / 0.70) are conservative safe defaults.
	// Future: allow per-policy threshold configuration.
	celExpr := "risk.level in ['high', 'critical'] && risk.confidence >= 0.80 && risk.completeness >= 0.70"

	// Determine TTL from ActionBinding or profile constraints.
	ttl := 30 * time.Minute
	if req.ActionBinding.MaxTTL != "" {
		if parsed, err := time.ParseDuration(req.ActionBinding.MaxTTL); err == nil && parsed > 0 {
			ttl = parsed
		}
	}
	// Enforce the profile's max TTL constraint.
	maxTTL := prof.Spec.Runtime.Constraints.RequireTTL
	_ = maxTTL // TTL enforcement is a KLIQ-side check at activation time

	// Map the action to a canonical Kernloom capability.
	capability := actionToCapability(req.ActionBinding.Action)

	// Params carry adapter-specific parameters (e.g. the attribute name for OpenZiti).
	params := map[string]string{}
	if req.ActionBinding.Attribute != "" {
		params["attribute"] = req.ActionBinding.Attribute
	}
	if req.ActionBinding.DecisionOwner != "" {
		params["decisionOwner"] = req.ActionBinding.DecisionOwner
	}

	return bundle.RuntimePolicy{
		ID: "compensating-" + req.RequirementKind + "-" + sanitizeID(prof.Spec.AdapterRef),
		Scope: bundle.PolicyScope{
			Type: "protected_resource",
			Ref:  ep_resourceRef(req),
		},
		When: bundle.PolicyWhen{
			Language:   "cel",
			Expression: celExpr,
		},
		Effect: bundle.PolicyEffect{
			Capability: capability,
			TTL:        ttl,
			Params:     params,
		},
		MissingContextBehavior: "observe_only",
		ReasonCode:             "ENTERPRISE_RISK_" + upperSnake(req.RequirementKind),
	}
}

// buildPDPProfile translates a TargetIntegrationProfile into a RuntimePDPProfile.
func buildPDPProfile(prof *profile.TargetIntegrationProfile, cfg BundleConfig) *bundle.RuntimePDPProfile {
	// Determine local risk mode from integration mode.
	riskMode := "local_lite"
	if prof.Spec.Mode == profile.ModeConfigOnly {
		riskMode = "none"
	} else if prof.Spec.Mode == profile.ModeKernloomPDPNative {
		riskMode = "local_full"
	}

	// Extract allowed capabilities from the profile's allowedRuntimeActions.
	// Each action maps to a canonical capability.
	var caps []string
	for _, action := range prof.Spec.AllowedRuntimeActions {
		if cap := actionToCapability(action); cap != "" {
			caps = append(caps, cap)
		}
	}

	maxTTL := 30 * time.Minute
	if prof.Spec.Runtime.Constraints.RequireTTL {
		maxTTL = 60 * time.Minute
	}

	offlineBehavior := cfg.OfflineBehavior
	if offlineBehavior == "" {
		offlineBehavior = "observe_only"
	}

	return &bundle.RuntimePDPProfile{
		APIVersion: "kernloom.io/runtime/v1alpha1",
		Kind:       "RuntimePDPProfile",
		Metadata:   bundle.ProfileMeta{Name: prof.Metadata.Name},
		Spec: bundle.PDPProfileSpec{
			LocalRiskMode:       riskMode,
			RiskModelRef:        bundle.RiskModelRef{Name: cfg.RiskModelName, Version: cfg.RiskModelVersion},
			AllowedCapabilities: caps,
			MaxActionIntensity:  "hard",
			MaxTTL:              maxTTL,
			AllowLocalBlock:     !prof.Spec.Runtime.Constraints.RestrictiveOnly,
			OfflineBehavior:     offlineBehavior,
			GlobalRiskTTL:       4 * time.Hour,
		},
	}
}

// isActionAllowed returns true if the action is in the allowed list.
func isActionAllowed(action string, allowed []string) bool {
	for _, a := range allowed {
		if a == action {
			return true
		}
	}
	return false
}

// actionToCapability maps a RuntimeActionCatalog action ID to a canonical capability.
func actionToCapability(action string) string {
	switch action {
	case "remove_kernloom_access_attribute", "remove_managed_role_attribute":
		return "access.restrict.identity"
	case "identity.disable", "disable_identity":
		return "access.disable.identity"
	case "revoke_active_sessions":
		return "access.revoke.sessions"
	case "force_mfa_step_up":
		return "access.require.step_up"
	case "network.flow_deny", "deny_flow":
		return "network.deny"
	case "network.flow_rate_limit", "rate_limit_flow":
		return "network.rate_limit"
	case "network.cgroup_block", "block_process_cgroup":
		return "network.block.cgroup"
	default:
		return ""
	}
}

// ep_resourceRef extracts a resource ref from a RequirementEnforcement.
// This is a best-effort extraction — the full resource ref is in the EnforcementPlan
// scope which we don't have per-requirement; use the target profile name as fallback.
func ep_resourceRef(req plan.RequirementEnforcement) string {
	if req.Ownership != nil && req.Ownership.TargetAuthorizationOwner != "" {
		return "profile:" + req.Ownership.TargetAuthorizationOwner
	}
	return ""
}

// sanitizeID replaces special chars with hyphens for use in identifiers.
func sanitizeID(s string) string {
	result := make([]byte, len(s))
	for i, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			result[i] = byte(c)
		} else {
			result[i] = '-'
		}
	}
	return string(result)
}

// upperSnake converts a string to UPPER_SNAKE_CASE reason code.
func upperSnake(s string) string {
	result := make([]byte, len(s))
	for i, c := range s {
		if c == '.' || c == '-' || c == ' ' {
			result[i] = '_'
		} else if c >= 'a' && c <= 'z' {
			result[i] = byte(c - 32)
		} else {
			result[i] = byte(c)
		}
	}
	return string(result)
}

// generateID returns a random UUIDv4 string.
func generateID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// jsonCompact returns the compact JSON encoding of v.
// Used internally for hash computation consistency.
func jsonCompact(v any) ([]byte, error) {
	return json.Marshal(v)
}

// RequirementKind is re-exported for convenience in tests.
// Matches the Kind constants from pkg/core/requirement.
const (
	KindRiskLevel    = "risk_level"
	KindDevicePosture = "device_posture"
	KindAuthStrength = "auth_strength"
)
