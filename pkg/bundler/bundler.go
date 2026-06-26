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
	"strconv"
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
	Name              string
	NodeID            string
	Generation        int
	IssuedAt          time.Time
	DefaultEffect     string
	DefaultTTL        time.Duration
	RegistrySnapshot  contracts.RegistrySnapshot
	Guardrails        []contracts.RuntimeGuardrail
	AccessPolicies    []contracts.RuntimeAccessPolicy
	DetectionRules    []contracts.RuntimeDetectionRule
	ResponseRules     []contracts.RuntimeResponseRule
	AlertRoutes       []contracts.RuntimeAlertRoute
	AutonomyLifecycle *contracts.RuntimeAutonomyLifecycleSpec
	GapMetadata       []contracts.RuntimeGapMetadata
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
	AccessPolicies         []contracts.RuntimeAccessPolicy
	DetectionRules         []contracts.RuntimeDetectionRule
	ResponseRules          []contracts.RuntimeResponseRule
	AlertRoutes            []contracts.RuntimeAlertRoute
	AutonomyLifecycle      *contracts.RuntimeAutonomyLifecycleSpec
	GapMetadata            []contracts.RuntimeGapMetadata
}

func BuildPolicyPack(ep *plan.EnforcementPlan, prof *profile.TargetIntegrationProfile, cfg RuntimePolicyConfig) (contracts.RuntimePolicyPack, error) {
	if ep == nil {
		return contracts.RuntimePolicyPack{}, fmt.Errorf("bundler: EnforcementPlan must not be nil")
	}
	if !ep.Spec.Summary.Deployable {
		return contracts.RuntimePolicyPack{}, fmt.Errorf("bundler: target %q is not deployable: unsupported %s", ep.Metadata.Target, strings.Join(ep.Spec.Summary.Unsupported, ","))
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
			DefaultEffect:     defaultEffect,
			Guardrails:        append([]contracts.RuntimeGuardrail(nil), cfg.Guardrails...),
			AccessPolicies:    append([]contracts.RuntimeAccessPolicy(nil), cfg.AccessPolicies...),
			DetectionRules:    append([]contracts.RuntimeDetectionRule(nil), cfg.DetectionRules...),
			ResponseRules:     append([]contracts.RuntimeResponseRule(nil), cfg.ResponseRules...),
			AlertRoutes:       append([]contracts.RuntimeAlertRoute(nil), cfg.AlertRoutes...),
			AutonomyLifecycle: cfg.AutonomyLifecycle,
			GapMetadata:       append([]contracts.RuntimeGapMetadata(nil), cfg.GapMetadata...),
		},
	}
	if len(pack.Spec.GapMetadata) == 0 {
		pack.Spec.GapMetadata = GapMetadataFromPlan(ep)
	}

	for _, req := range ep.Spec.Requirements {
		if req.Status != plan.StatusCompensatingControl {
			continue
		}
		if explicitResponseCoversRequirement(req, cfg.ResponseRules, cfg.DetectionRules) {
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
	if err := addResponseRuntimeRules(&pack); err != nil {
		return contracts.RuntimePolicyPack{}, err
	}
	addResponseCapabilities(&pack)
	addAutonomyLifecycleCapabilities(&pack)
	if len(pack.Spec.AccessPolicies) > 0 {
		addCapability(&pack, "access.policy.apply")
		addCapability(&pack, "access.policy.drift_check")
	}

	snapshot, err := validationSnapshot(cfg.RegistrySnapshot)
	if err != nil {
		return contracts.RuntimePolicyPack{}, err
	}
	if err := normalizeBuiltRuntimePolicyPackContracts(&pack, snapshot); err != nil {
		return contracts.RuntimePolicyPack{}, err
	}
	if err := validateBuiltRuntimePolicyPack(pack, snapshot); err != nil {
		return contracts.RuntimePolicyPack{}, err
	}
	if err := validateResponseActionsAllowedByProfile(pack.Spec.ResponseRules, prof); err != nil {
		return contracts.RuntimePolicyPack{}, err
	}
	if err := validateAutonomyActionsAllowedByProfile(pack.Spec.AutonomyLifecycle, prof); err != nil {
		return contracts.RuntimePolicyPack{}, err
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
		NodeID:            cfg.NodeID,
		Generation:        cfg.Generation,
		IssuedAt:          issuedAt,
		DefaultTTL:        cfg.DefaultTTL,
		RegistrySnapshot:  registrySnapshot,
		Guardrails:        cfg.Guardrails,
		AccessPolicies:    cfg.AccessPolicies,
		DetectionRules:    cfg.DetectionRules,
		ResponseRules:     cfg.ResponseRules,
		AlertRoutes:       cfg.AlertRoutes,
		AutonomyLifecycle: cfg.AutonomyLifecycle,
		GapMetadata:       cfg.GapMetadata,
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

func GapMetadataFromPlan(ep *plan.EnforcementPlan) []contracts.RuntimeGapMetadata {
	if ep == nil {
		return nil
	}
	out := make([]contracts.RuntimeGapMetadata, 0)
	for _, req := range ep.Spec.Requirements {
		gapType, behavior, severity := gapMetadataClassification(req)
		if gapType == "" {
			continue
		}
		meta := map[string]string{}
		if req.Capability != "" {
			meta["capability"] = req.Capability
		}
		if req.Fidelity != "" {
			meta["fidelity"] = req.Fidelity
		}
		if req.Downgrade != nil {
			meta["from"] = req.Downgrade.From
			meta["to"] = req.Downgrade.To
		}
		out = append(out, contracts.RuntimeGapMetadata{
			ID:          "gap-" + sanitizeID(req.ID),
			Type:        gapType,
			Behavior:    behavior,
			Target:      ep.Metadata.Target,
			Requirement: req.ID,
			Severity:    severity,
			Deployable:  ep.Spec.Summary.Deployable,
			Reason:      gapReason(req),
			Meta:        meta,
		})
	}
	if len(out) == 0 {
		out = append(out, contracts.RuntimeGapMetadata{
			ID:         "no-gaps",
			Type:       "none",
			Behavior:   "deploy",
			Target:     ep.Metadata.Target,
			Severity:   "none",
			Deployable: ep.Spec.Summary.Deployable,
			Reason:     "no gaps detected for this target plan",
		})
	}
	return out
}

func gapMetadataClassification(req plan.RequirementEnforcement) (gapType, behavior, severity string) {
	switch req.Status {
	case plan.StatusUnsupported:
		return "enforcement_gap", "fail_closed", "high"
	case plan.StatusPartial:
		return "semantic_downgrade", "require_review", "medium"
	case plan.StatusDelegated:
		return "delegation_gap", "report", "low"
	case plan.StatusCompensatingControl:
		return "compensating_control", "report", "low"
	default:
		return "", "", ""
	}
}

func gapReason(req plan.RequirementEnforcement) string {
	if req.Downgrade != nil && req.Downgrade.Reason != "" {
		return req.Downgrade.Reason
	}
	if len(req.RuntimeNotes) > 0 {
		return strings.Join(req.RuntimeNotes, " ")
	}
	switch req.Status {
	case plan.StatusUnsupported:
		return "requirement cannot be satisfied by this target"
	case plan.StatusPartial:
		return "requirement is implemented with reduced semantic fidelity"
	case plan.StatusDelegated:
		return "requirement evaluation is delegated to target PDP"
	case plan.StatusCompensatingControl:
		return "requirement is enforced through a compensating runtime action"
	default:
		return ""
	}
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
	case "network.flow_deny", "deny_flow", "network.block_source":
		return "enforce.traffic.drop", "block", true
	case "network.cgroup_block", "block_process_cgroup":
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

func addResponseRuntimeRules(pack *contracts.RuntimePolicyPack) error {
	if pack == nil {
		return nil
	}
	detections := make(map[string]contracts.RuntimeDetectionRule, len(pack.Spec.DetectionRules))
	for _, detection := range pack.Spec.DetectionRules {
		if detection.ID != "" {
			detections[detection.ID] = detection
		}
	}
	seen := map[string]bool{}
	for _, existing := range pack.Spec.Rules {
		if existing.ID != "" {
			seen[existing.ID] = true
		}
	}
	for _, responseRule := range pack.Spec.ResponseRules {
		if !responseRuleHasEnforcement(responseRule) {
			continue
		}
		baseExpr, detectionID, err := responseRuntimeExpression(responseRule, detections)
		if err != nil {
			return err
		}
		detection, hasDetection := detectionByRef(detectionID, detections)
		for i, action := range responseRule.Then {
			if !strings.HasPrefix(action.ID, "enforce.") {
				continue
			}
			runtimeAction, err := runtimeActionFromResponse(responseRule, action, detectionID, detection, hasDetection)
			if err != nil {
				return err
			}
			when := baseExpr
			if hasDetection {
				if projected := dryRunProjectionExpression(action, detection); projected != "" {
					when = "(" + when + " || " + projected + ")"
				}
			}
			if previous := previousActionExpression(action); previous != "" {
				when = "(" + when + ") && (" + previous + ")"
			}
			if quality := responseQualityExpression(action); quality != "" {
				when = "(" + when + ") && (" + quality + ")"
			}
			id := "response-" + sanitizeID(responseRule.ID) + "-" + sanitizeID(action.ID)
			if len(responseRule.Then) > 1 {
				id = fmt.Sprintf("%s-%d", id, i+1)
			}
			for seen[id] {
				id += "-next"
			}
			seen[id] = true
			pack.Spec.Rules = append(pack.Spec.Rules, contracts.RuntimePolicyRule{
				ID:          id,
				Description: "RuntimePDP enforcement compiled from ResponsePolicy " + responseRule.ID,
				When:        when,
				Then:        runtimeAction,
				ReasonCodes: responseRuntimeReasonCodes(responseRule, detectionID),
			})
			addCapability(pack, runtimeAction.Capability)
		}
	}
	return nil
}

func responseRuleHasEnforcement(rule contracts.RuntimeResponseRule) bool {
	for _, action := range rule.Then {
		if strings.HasPrefix(action.ID, "enforce.") {
			return true
		}
	}
	return false
}

func explicitResponseCoversRequirement(req plan.RequirementEnforcement, responses []contracts.RuntimeResponseRule, detections []contracts.RuntimeDetectionRule) bool {
	domain := requirementRuntimeDomain(req)
	if domain == "" {
		return false
	}
	byID := make(map[string]contracts.RuntimeDetectionRule, len(detections))
	for _, detection := range detections {
		if detection.ID != "" {
			byID[detection.ID] = detection
		}
	}
	for _, response := range responses {
		if !responseRuleHasEnforcement(response) {
			continue
		}
		detection, ok := detectionByRef(strings.TrimSpace(response.When.Detection), byID)
		if !ok {
			continue
		}
		if detectionRuntimeDomain(detection) == domain {
			return true
		}
	}
	return false
}

func requirementRuntimeDomain(req plan.RequirementEnforcement) string {
	switch strings.TrimSpace(req.RequirementKind) {
	case "risk_level":
		return "risk.level"
	case "device_posture":
		return "device.posture.status"
	case "auth_strength":
		return "session.authentication.strength"
	default:
		return ""
	}
}

func detectionRuntimeDomain(detection contracts.RuntimeDetectionRule) string {
	if strings.TrimSpace(detection.Type) != "metric.threshold" {
		return ""
	}
	key := stringParamAny(detection.Params, "key", "signal", "metric")
	return normalizeRuntimeMetricKey(key)
}

func responseRuntimeExpression(rule contracts.RuntimeResponseRule, detections map[string]contracts.RuntimeDetectionRule) (expr, detectionID string, err error) {
	detectionID = strings.TrimSpace(rule.When.Detection)
	if detectionID == "" {
		return "", "", fmt.Errorf("bundler: response rule %q has enforcement actions but no detection trigger", rule.ID)
	}
	detection, ok := detectionByRef(detectionID, detections)
	if !ok {
		return detectionFactExpression(detectionID), detectionID, nil
	}
	if expr := directDetectionExpression(detection); expr != "" {
		return expr, detection.ID, nil
	}
	return detectionFactExpression(detection.ID), detection.ID, nil
}

func detectionByRef(ref string, detections map[string]contracts.RuntimeDetectionRule) (contracts.RuntimeDetectionRule, bool) {
	if detection, ok := detections[ref]; ok {
		return detection, true
	}
	for id, detection := range detections {
		if strings.HasSuffix(ref, "/"+id) {
			return detection, true
		}
	}
	return contracts.RuntimeDetectionRule{}, false
}

func directDetectionExpression(detection contracts.RuntimeDetectionRule) string {
	switch strings.TrimSpace(detection.Type) {
	case "metric.threshold":
		key := stringParamAny(detection.Params, "key", "signal", "metric")
		op := stringParamAny(detection.Params, "operator", "op")
		if op == "" {
			op = "gt"
		}
		value, ok := anyParam(detection.Params, "value", "threshold")
		if !ok {
			return ""
		}
		switch normalizeRuntimeMetricKey(key) {
		case "risk.level":
			return celCompare("risk.level", op, value)
		case "risk.score":
			return celCompare("risk.score", op, value)
		}
	}
	return ""
}

func normalizeRuntimeMetricKey(key string) string {
	key = strings.TrimSpace(key)
	switch key {
	case "risk", "risk.level", "runtime.risk.level", "subject.risk.level":
		return "risk.level"
	case "risk.score", "runtime.risk.score", "subject.risk.score":
		return "risk.score"
	default:
		return key
	}
}

func detectionFactExpression(detectionID string) string {
	return "detections." + celIdentifier(detectionID) + ".active == true"
}

func runtimeActionFromResponse(rule contracts.RuntimeResponseRule, action contracts.RuntimeResponseAction, detectionID string, detection contracts.RuntimeDetectionRule, hasDetection bool) (contracts.RuntimeActionSpec, error) {
	capability := strings.TrimSpace(action.ID)
	if !strings.HasPrefix(capability, "enforce.") {
		return contracts.RuntimeActionSpec{}, fmt.Errorf("bundler: response rule %q action %q is not an enforcement action", rule.ID, action.ID)
	}
	params := copyAnyMap(action.Params)
	if params == nil {
		params = map[string]any{}
	}
	params["response_rule_id"] = rule.ID
	if detectionID != "" {
		params["detection_rule_id"] = detectionID
	}
	if hasDetection {
		if sourceClass := detectionSourceClass(detection); sourceClass != "" {
			params["source_class"] = sourceClass
			params["source_selector"] = sourceClass + "_source"
		}
	}
	if action.Target.Scope != "" {
		params["target_granularity"] = normalizeResponseTargetScope(action.Target.Scope)
	}
	if action.Target.Ref != "" {
		params["target_value"] = action.Target.Ref
		switch normalizeResponseTargetScope(action.Target.Scope) {
		case "", "source":
			params["source_id"] = action.Target.Ref
		}
	}
	return contracts.RuntimeActionSpec{
		Capability: capability,
		Level:      responseActionLevel(action, capability),
		TTL:        action.TTL,
		Params:     params,
	}, nil
}

func detectionSourceClass(detection contracts.RuntimeDetectionRule) string {
	selector := strings.TrimSpace(detection.Subject.Selector)
	if selector == "" {
		selector = strings.TrimSpace(fmt.Sprint(detection.Params["selector"]))
	}
	switch selector {
	case "unknown_source":
		return "unknown"
	case "known_subject", "known_subject_excluding_group":
		return "known"
	default:
		return ""
	}
}

func normalizeResponseTargetScope(scope string) string {
	scope = strings.TrimSpace(scope)
	switch scope {
	case "", "source", "source.ip", "source.identity_or_ip":
		return "source"
	default:
		return scope
	}
}

func responseActionLevel(action contracts.RuntimeResponseAction, capability string) string {
	switch strings.TrimSpace(action.Severity) {
	case "soft", "hard", "block":
		return action.Severity
	}
	switch capability {
	case "enforce.traffic.rate_limit", "enforce.traffic.connection_limit", "enforce.traffic.bandwidth_limit":
		return "hard"
	case "enforce.traffic.drop", "enforce.access.deny", "enforce.network.quarantine", "enforce.identity.disable":
		return "block"
	default:
		return "hard"
	}
}

func previousActionExpression(action contracts.RuntimeResponseAction) string {
	if !boolParam(action.Params, "previous_action_active") {
		return ""
	}
	previous := strings.TrimSpace(fmt.Sprint(action.Params["previous_action_id"]))
	if previous == "" || previous == "<nil>" {
		return ""
	}
	ledgerExpr := "actions." + celIdentifier(previous) + ".active == true"
	if !allowsLocalRuntimeStateEvidence(action.Params) {
		return ledgerExpr
	}
	if localExpr := localRuntimeStateExpression(previous); localExpr != "" {
		return ledgerExpr + " || " + localExpr
	}
	return ledgerExpr
}

func responseQualityExpression(action contracts.RuntimeResponseAction) string {
	var parts []string
	if minConfidence, ok := floatParamAny(action.Params, "min_risk_confidence"); ok && minConfidence > 0 {
		parts = append(parts, fmt.Sprintf("risk.confidence >= %.3g", minConfidence))
	}
	if maxAgeSeconds, ok := intParamAny(action.Params, "max_risk_age_seconds"); ok && maxAgeSeconds > 0 {
		parts = append(parts, fmt.Sprintf("risk.age_seconds <= %d", maxAgeSeconds))
	}
	if minSignals, ok := intParamAny(action.Params, "min_independent_signals"); ok && minSignals > 0 {
		parts = append(parts, fmt.Sprintf("risk.independent_signal_count >= %d", minSignals))
	}
	return strings.Join(parts, " && ")
}

func dryRunProjectionExpression(action contracts.RuntimeResponseAction, detection contracts.RuntimeDetectionRule) string {
	if strings.TrimSpace(detection.Type) != "source.rate_limit_drops_sustained" {
		return ""
	}
	if !boolParam(action.Params, "previous_action_active") || !allowsLocalRuntimeStateEvidence(action.Params) {
		return ""
	}
	previous := strings.TrimSpace(fmt.Sprint(action.Params["previous_action_id"]))
	if previous == "" || previous == "<nil>" {
		return ""
	}
	key := "actions." + celIdentifier(previous)
	windowSeconds := int(detection.Window.Duration.Seconds())
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	return fmt.Sprintf("(%s.active == true && %s.dry_run == true && %s.elapsed_seconds >= %d && risk.level in ['medium', 'high', 'critical'])", key, key, key, windowSeconds)
}

func allowsLocalRuntimeStateEvidence(params map[string]any) bool {
	raw, ok := params["previous_action_evidence"]
	if !ok {
		return false
	}
	for _, value := range anyStringList(raw) {
		switch strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_") {
		case "local_runtime_state", "local_enforcement_state", "local_state":
			return true
		}
	}
	return false
}

func localRuntimeStateExpression(actionID string) string {
	switch strings.TrimSpace(actionID) {
	case "enforce.traffic.rate_limit":
		return "fsm.current_level in ['soft', 'hard']"
	case "enforce.traffic.drop", "enforce.access.deny", "enforce.network.quarantine", "enforce.identity.disable":
		return "fsm.current_level == 'block'"
	default:
		return ""
	}
}

func responseRuntimeReasonCodes(rule contracts.RuntimeResponseRule, detectionID string) []string {
	out := append([]string{"response_policy_enforcement"}, rule.ReasonCodes...)
	if detectionID != "" {
		out = append(out, "detection_"+sanitizeReasonCode(detectionID))
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

func addResponseCapabilities(pack *contracts.RuntimePolicyPack) {
	for _, response := range pack.Spec.ResponseRules {
		for _, action := range response.Then {
			if strings.HasPrefix(action.ID, "enforce.") {
				addCapability(pack, action.ID)
			}
		}
	}
}

func addAutonomyLifecycleCapabilities(pack *contracts.RuntimePolicyPack) {
	if pack == nil || pack.Spec.AutonomyLifecycle == nil {
		return
	}
	for _, hold := range pack.Spec.AutonomyLifecycle.Hold {
		addCapability(pack, hold.Action.Capability)
	}
}

func validateResponseActionsAllowedByProfile(rules []contracts.RuntimeResponseRule, prof *profile.TargetIntegrationProfile) error {
	for _, rule := range rules {
		for _, action := range rule.Then {
			if !strings.HasPrefix(action.ID, "enforce.") {
				continue
			}
			if !ProfileAllowsRuntimeCapability(prof, action.ID) {
				return fmt.Errorf("bundler: response rule %q action %q is not allowed by profile %q", rule.ID, action.ID, prof.Metadata.Name)
			}
		}
	}
	return nil
}

func validateAutonomyActionsAllowedByProfile(lifecycle *contracts.RuntimeAutonomyLifecycleSpec, prof *profile.TargetIntegrationProfile) error {
	if lifecycle == nil {
		return nil
	}
	for _, hold := range lifecycle.Hold {
		capability := hold.Action.Capability
		if !strings.HasPrefix(capability, "enforce.") {
			continue
		}
		if !ProfileAllowsRuntimeCapability(prof, capability) {
			return fmt.Errorf("bundler: autonomy hold %q action %q is not allowed by profile %q", hold.ID, capability, prof.Metadata.Name)
		}
	}
	return nil
}

func ProfileAllowsRuntimeCapability(prof *profile.TargetIntegrationProfile, capability string) bool {
	if prof == nil || strings.TrimSpace(capability) == "" {
		return false
	}
	for _, allowed := range prof.Spec.AllowedRuntimeActions {
		if allowed == capability {
			return true
		}
		mappedCapability, _, ok := actionToCapability(allowed)
		if ok && mappedCapability == capability {
			return true
		}
	}
	return false
}

func allowsBlock(pack contracts.RuntimePolicyPack) bool {
	for _, rule := range pack.Spec.Rules {
		if rule.Then.Level == "block" || rule.Then.Capability == "enforce.access.deny" {
			return true
		}
	}
	if pack.Spec.AutonomyLifecycle != nil {
		for _, hold := range pack.Spec.AutonomyLifecycle.Hold {
			if hold.Action.Level == "block" || hold.Action.Capability == "enforce.access.deny" {
				return true
			}
		}
	}
	return false
}

func celCompare(left, op string, value any) string {
	op = strings.TrimSpace(op)
	switch op {
	case "eq", "equals", "is":
		return left + " == " + celLiteral(value)
	case "neq", "not":
		return left + " != " + celLiteral(value)
	case "gte":
		return left + " >= " + celLiteral(value)
	case "lte":
		return left + " <= " + celLiteral(value)
	case "lt":
		return left + " < " + celLiteral(value)
	case "in":
		return left + " in " + celLiteralList(value)
	case "not_in":
		return "!(" + left + " in " + celLiteralList(value) + ")"
	default:
		return left + " > " + celLiteral(value)
	}
}

func celLiteral(value any) string {
	switch v := value.(type) {
	case string:
		return celQuote(v)
	case fmt.Stringer:
		return celQuote(v.String())
	default:
		return fmt.Sprint(v)
	}
}

func celLiteralList(value any) string {
	values := anyStringList(value)
	if len(values) == 0 {
		return "[]"
	}
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, celQuote(value))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func celQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `'`, `\'`)
	return "'" + value + "'"
}

func celIdentifier(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var out strings.Builder
	for _, r := range value {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			out.WriteRune(r)
			continue
		}
		out.WriteByte('_')
	}
	id := strings.Trim(out.String(), "_")
	if id == "" {
		return "value"
	}
	first := id[0]
	if first >= '0' && first <= '9' {
		return "v_" + id
	}
	return id
}

func copyAnyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func stringParamAny(params map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := params[key]; ok {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}

func anyParam(params map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		value, ok := params[key]
		if ok {
			return value, true
		}
	}
	return nil, false
}

func intParamAny(params map[string]any, keys ...string) (int, bool) {
	value, ok := anyParam(params, keys...)
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case float32:
		return int(typed), true
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		parsed, err := strconv.Atoi(strings.TrimSpace(fmt.Sprint(typed)))
		return parsed, err == nil
	}
}

func floatParamAny(params map[string]any, keys ...string) (float64, bool) {
	value, ok := anyParam(params, keys...)
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed, err == nil
	default:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(fmt.Sprint(typed)), 64)
		return parsed, err == nil
	}
}

func anyStringList(value any) []string {
	switch typed := value.(type) {
	case []string:
		return cleanStringList(typed)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, fmt.Sprint(item))
		}
		return cleanStringList(out)
	case string:
		return cleanStringList(strings.Split(strings.Trim(typed, "[]"), ","))
	default:
		return cleanStringList([]string{fmt.Sprint(value)})
	}
}

func cleanStringList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.Trim(value, " \t\r\n\"'")
		if value != "" && value != "<nil>" {
			out = append(out, value)
		}
	}
	return out
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
