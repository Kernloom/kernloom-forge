// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package bundler translates Forge governance plans into KLIQ runtime
// contracts. The EnforcementPlan remains the operator/audit artifact; the
// RuntimePolicyPack and RuntimeBundle are the executable Forge-to-KLIQ wire
// artifacts.
package bundler

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom-forge/pkg/core/plan"
	"github.com/kernloom/kernloom-forge/pkg/core/profile"
	registries "github.com/kernloom/kernloom-registries"
)

const (
	defaultPolicyEffect = "deny"
	defaultPDPMode      = "active"
	defaultFailover     = "fail_static"
	defaultBundleTTL    = 24 * time.Hour
)

type RuntimePolicyConfig struct {
	Name          string
	NodeID        string
	Generation    int
	IssuedAt      time.Time
	DefaultEffect string
	DefaultTTL    time.Duration
	Guardrails    []contracts.RuntimeGuardrail
}

type BundleConfig struct {
	NodeID                 string
	TenantID               string
	Generation             int
	IssuedAt               time.Time
	ValidFor               time.Duration
	ContextRegistryVersion string
	PreferredAdapters      []string
	DisabledAdapters       []string
	RuntimePDPMode         string
	FailoverBehavior       string
	DefaultTTL             time.Duration
	RegistrySnapshot       contracts.RegistrySnapshot
	BaselineEnabled        bool
	GraphEnabled           bool
	Guardrails             []contracts.RuntimeGuardrail
}

func BuildPolicyPack(ep *plan.EnforcementPlan, prof *profile.TargetIntegrationProfile, cfg RuntimePolicyConfig) (contracts.RuntimePolicyPack, error) {
	if ep == nil {
		return contracts.RuntimePolicyPack{}, fmt.Errorf("bundler: EnforcementPlan must not be nil")
	}
	if prof == nil {
		return contracts.RuntimePolicyPack{}, fmt.Errorf("bundler: TargetIntegrationProfile must not be nil")
	}
	issuedAt := cfg.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	}
	name := cfg.Name
	if name == "" {
		name = ep.Metadata.SourcePolicy + "-" + prof.Metadata.Name
	}
	defaultEffect := cfg.DefaultEffect
	if defaultEffect == "" {
		defaultEffect = defaultPolicyEffect
	}
	defaultTTL := cfg.DefaultTTL
	if defaultTTL <= 0 {
		defaultTTL = defaultTTLForProfile(prof)
	}

	pack := contracts.RuntimePolicyPack{
		TypeMeta: contracts.TypeMeta{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindRuntimePolicyPack,
		},
		Metadata: contracts.ObjectMeta{
			Name:       name,
			NodeID:     cfg.NodeID,
			Generation: cfg.Generation,
			IssuedAt:   issuedAt,
			Labels: map[string]string{
				"forge.kernloom.io/source_policy": ep.Metadata.SourcePolicy,
				"forge.kernloom.io/target":        ep.Metadata.Target,
				"forge.kernloom.io/adapter":       prof.Spec.AdapterRef,
			},
		},
		Spec: contracts.RuntimePolicyPackSpec{
			DefaultEffect: defaultEffect,
			Guardrails:    append([]contracts.RuntimeGuardrail(nil), cfg.Guardrails...),
		},
	}

	for _, req := range ep.Spec.Requirements {
		if req.Status != plan.StatusCompensatingControl {
			continue
		}
		if req.ActionBinding == nil {
			return contracts.RuntimePolicyPack{}, fmt.Errorf("bundler: compensating requirement %q has no action binding", req.ID)
		}
		if !prof.IsActionAllowed(req.ActionBinding.Action) {
			return contracts.RuntimePolicyPack{}, fmt.Errorf("bundler: action %q for requirement %q is not allowed by profile %q", req.ActionBinding.Action, req.ID, prof.Metadata.Name)
		}
		action, err := actionSpecForBinding(req, defaultTTL)
		if err != nil {
			return contracts.RuntimePolicyPack{}, err
		}
		expr := violationExpression(req)
		if expr == "" {
			return contracts.RuntimePolicyPack{}, fmt.Errorf("bundler: no runtime expression for compensating requirement %q", req.ID)
		}
		pack.Spec.Rules = append(pack.Spec.Rules, contracts.RuntimePolicyRule{
			ID:          "compensating-" + sanitizeID(req.ID) + "-" + sanitizeID(prof.Metadata.Name),
			Description: "Forge compensating control for " + req.ID,
			When:        expr,
			Then:        action,
			ReasonCodes: reasonCodesForRequirement(req),
		})
		addCapability(&pack, action.Capability)
	}

	return pack, nil
}

func Build(ep *plan.EnforcementPlan, prof *profile.TargetIntegrationProfile, cfg BundleConfig, privKey ed25519.PrivateKey) (contracts.RuntimeBundle, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return contracts.RuntimeBundle{}, fmt.Errorf("bundler: invalid Ed25519 private key size: got %d want %d", len(privKey), ed25519.PrivateKeySize)
	}
	if cfg.NodeID == "" {
		return contracts.RuntimeBundle{}, fmt.Errorf("bundler: NodeID is required")
	}
	if cfg.Generation <= 0 {
		return contracts.RuntimeBundle{}, fmt.Errorf("bundler: Generation must be > 0")
	}
	issuedAt := cfg.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	}
	validFor := cfg.ValidFor
	if validFor <= 0 {
		validFor = defaultBundleTTL
	}
	pdpMode := cfg.RuntimePDPMode
	if pdpMode == "" {
		pdpMode = defaultPDPMode
	}
	failover := cfg.FailoverBehavior
	if failover == "" {
		failover = defaultFailover
	}
	registrySnapshot := cfg.RegistrySnapshot
	if registrySnapshot.Ref.Name == "" {
		var err error
		registrySnapshot, err = registries.EmbeddedSnapshot()
		if err != nil {
			return contracts.RuntimeBundle{}, fmt.Errorf("bundler: load registry snapshot: %w", err)
		}
	}
	contextRegistryVersion := cfg.ContextRegistryVersion
	if contextRegistryVersion == "" {
		contextRegistryVersion = registrySnapshot.ContextVersion
	}

	pack, err := BuildPolicyPack(ep, prof, RuntimePolicyConfig{
		NodeID:     cfg.NodeID,
		Generation: cfg.Generation,
		IssuedAt:   issuedAt,
		DefaultTTL: cfg.DefaultTTL,
		Guardrails: cfg.Guardrails,
	})
	if err != nil {
		return contracts.RuntimeBundle{}, err
	}

	bundle := contracts.RuntimeBundle{
		TypeMeta: contracts.TypeMeta{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindRuntimeBundle,
		},
		Metadata: contracts.ObjectMeta{
			ID:         generateID(),
			Name:       pack.Metadata.Name,
			NodeID:     cfg.NodeID,
			Generation: cfg.Generation,
			IssuedAt:   issuedAt,
			ExpiresAt:  issuedAt.Add(validFor),
			Labels: map[string]string{
				"forge.kernloom.io/source_policy": ep.Metadata.SourcePolicy,
				"forge.kernloom.io/target":        ep.Metadata.Target,
				"forge.kernloom.io/adapter":       prof.Spec.AdapterRef,
			},
		},
		Spec: contracts.RuntimeBundleSpec{
			RuntimePolicyPack: pack,
			Registry:          registrySnapshot.Ref,
			RegistrySnapshot:  registrySnapshot,
			RuntimePDPProfile: contracts.RuntimePDPProfile{
				Name: prof.Metadata.Name,
				Mode: pdpMode,
				Variables: []contracts.RuntimeInput{
					{Name: "risk", Required: true, Source: "risk_assessment"},
					{Name: "signals", Required: false, Source: "runtime_signals"},
					{Name: "fsm", Required: false, Source: "local_analyzer"},
				},
			},
			ContextRegistryVersion: contextRegistryVersion,
			AdapterSelector: contracts.AdapterSelector{
				RequiredCapabilities: pack.Spec.CapabilitiesRequired,
				PreferredAdapters:    append([]string(nil), cfg.PreferredAdapters...),
				DisabledAdapters:     append([]string(nil), cfg.DisabledAdapters...),
			},
			BaselineLifecycle: contracts.BaselineLifecycle{
				Mode:             enabledMode(cfg.BaselineEnabled),
				AllowLocalFreeze: cfg.BaselineEnabled,
			},
			GraphLifecycle: contracts.GraphLifecycle{
				Mode: cfgGraphMode(cfg.GraphEnabled),
			},
			EnforcementBounds: contracts.EnforcementBounds{
				AllowBlock: allowsBlock(pack),
			},
			Failover: contracts.FailoverConfig{
				Behavior: failover,
			},
		},
	}
	return contracts.SignRuntimeBundle(bundle, "forge-runtime", privKey)
}

func Verify(bundle contracts.RuntimeBundle, pubKey ed25519.PublicKey, now time.Time) error {
	return contracts.VerifyRuntimeBundle(bundle, pubKey, now)
}

func VerifyNotExpired(bundle contracts.RuntimeBundle, now time.Time) error {
	if !bundle.Metadata.ExpiresAt.IsZero() && !now.Before(bundle.Metadata.ExpiresAt) {
		return fmt.Errorf("bundle expired at %s", bundle.Metadata.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

func actionSpecForBinding(req plan.RequirementEnforcement, defaultTTL time.Duration) (contracts.RuntimeActionSpec, error) {
	capability, level, ok := actionToCapability(req.ActionBinding.Action)
	if !ok {
		return contracts.RuntimeActionSpec{}, fmt.Errorf("bundler: action %q has no KLIQ runtime capability mapping", req.ActionBinding.Action)
	}
	ttl := defaultTTL
	if req.ActionBinding.MaxTTL != "" {
		parsed, err := time.ParseDuration(req.ActionBinding.MaxTTL)
		if err != nil {
			return contracts.RuntimeActionSpec{}, fmt.Errorf("bundler: parse maxTTL for requirement %q: %w", req.ID, err)
		}
		if parsed > 0 {
			ttl = parsed
		}
	}
	params := map[string]any{
		"forge_requirement_id": req.ID,
		"forge_action":         req.ActionBinding.Action,
	}
	if req.ActionBinding.Attribute != "" {
		params["attribute"] = req.ActionBinding.Attribute
	}
	if req.ActionBinding.DecisionOwner != "" {
		params["decision_owner"] = req.ActionBinding.DecisionOwner
	}
	return contracts.RuntimeActionSpec{
		Capability: capability,
		Level:      level,
		TTL:        contracts.NewDuration(ttl),
		Params:     params,
	}, nil
}

func actionToCapability(action string) (capability, level string, ok bool) {
	switch action {
	case "network.flow_rate_limit", "rate_limit_flow", "network.rate_limit_source":
		return "enforce.traffic.rate_limit", "hard", true
	case "network.flow_deny", "deny_flow", "network.block_source", "network.cgroup_block", "block_process_cgroup":
		return "enforce.access.deny", "block", true
	case "remove_kernloom_access_attribute":
		return "enforce.access.deny", "block", true
	case "identity.disable", "disable_identity", "identity.account_disable":
		return "enforce.access.deny", "block", true
	case "revoke_active_sessions":
		return "enforce.access.deny", "hard", true
	default:
		return "", "", false
	}
}

func violationExpression(req plan.RequirementEnforcement) string {
	switch req.RequirementKind {
	case "risk_level":
		return "risk.level in ['high', 'critical']"
	case "device_posture":
		return "device.posture.status in ['degraded', 'unhealthy']"
	case "auth_strength":
		return "session.authentication.strength in ['none', 'password']"
	}
	if strings.TrimSpace(req.Requirement) == "" {
		return ""
	}
	return "!(" + req.Requirement + ")"
}

func reasonCodesForRequirement(req plan.RequirementEnforcement) []string {
	out := []string{"forge_compensating_control", "requirement_" + sanitizeReasonCode(req.ID)}
	switch req.RequirementKind {
	case "risk_level":
		out = append(out, "risk_high")
	case "device_posture":
		out = append(out, "device_posture_not_healthy")
	case "auth_strength":
		out = append(out, "auth_strength_insufficient")
	}
	return out
}

func sanitizeReasonCode(s string) string {
	return strings.ReplaceAll(sanitizeID(s), "-", "_")
}

func addCapability(pack *contracts.RuntimePolicyPack, cap string) {
	if cap == "" {
		return
	}
	for _, existing := range pack.Spec.CapabilitiesRequired {
		if existing == cap {
			return
		}
	}
	pack.Spec.CapabilitiesRequired = append(pack.Spec.CapabilitiesRequired, cap)
}

func allowsBlock(pack contracts.RuntimePolicyPack) bool {
	for _, rule := range pack.Spec.Rules {
		if rule.Then.Level == "block" || rule.Then.Capability == "enforce.access.deny" {
			return true
		}
	}
	return false
}

func defaultTTLForProfile(prof *profile.TargetIntegrationProfile) time.Duration {
	if prof.Spec.Mode == profile.ModeEnterpriseRiskOverlay {
		return 30 * time.Minute
	}
	return 30 * time.Second
}

func enabledMode(enabled bool) string {
	if enabled {
		return "managed"
	}
	return "disabled"
}

func cfgGraphMode(enabled bool) string {
	if enabled {
		return "managed"
	}
	return "disabled"
}

func generateID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func sanitizeID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var out strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			out.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			out.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(out.String(), "-")
}
