// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom-forge/internal/signing"
	"github.com/kernloom/kernloom-forge/pkg/bundler"
	"github.com/kernloom/kernloom-forge/pkg/compiler"
	"github.com/kernloom/kernloom-forge/pkg/configpdp"
	conformancefixtures "github.com/kernloom/kernloom-forge/pkg/conformance"
	"github.com/kernloom/kernloom-forge/pkg/core/guardrail"
	"github.com/kernloom/kernloom-forge/pkg/core/intent"
	"github.com/kernloom/kernloom-forge/pkg/core/plan"
	"github.com/kernloom/kernloom-forge/pkg/core/profile"
	"github.com/kernloom/kernloom-forge/pkg/core/requirement"
	"github.com/kernloom/kernloom-forge/pkg/core/response"
	"github.com/kernloom/kernloom-forge/pkg/report"
	registries "github.com/kernloom/kernloom-registries"
	"github.com/spf13/cobra"
)

func exportRuntimePolicyCmd() *cobra.Command {
	var policyFile, intentFile, intentBaseDir, adaptersDir, profilesDir, target, output string
	var guardrailFiles []string
	var detectionFiles []string
	var responseFiles []string
	var alertRouteFiles []string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "export-runtime-policy",
		Short: "Compile a KLIQ RuntimePolicyPack from an AccessPolicy and target profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			comp, plans, profiles, err := compilePlansFromInput(policyFile, intentFile, intentBaseDir, adaptersDir, profilesDir, guardrailFiles, detectionFiles, responseFiles, alertRouteFiles)
			if err != nil {
				return err
			}
			target = intentTargetOverride(comp, target)
			ep, prof, err := selectTarget(plans, profiles, target)
			if err != nil {
				return err
			}
			if err := validateRuntimeResponseReferences(comp.DetectionRules, comp.ResponseRules, comp.AlertRoutes); err != nil {
				return err
			}
			pack, err := bundler.BuildPolicyPack(ep, prof, bundler.RuntimePolicyConfig{
				Name:              comp.SourceName() + "-" + prof.Metadata.Name,
				IssuedAt:          time.Now().UTC(),
				DefaultTTL:        ttl,
				Guardrails:        comp.Guardrails,
				DetectionRules:    comp.DetectionRules,
				ResponseRules:     comp.ResponseRules,
				AlertRoutes:       comp.AlertRoutes,
				AutonomyLifecycle: comp.AutonomyLifecycle,
			})
			if err != nil {
				return err
			}
			emitRuntimePolicySupportWarnings(pack.Spec.AutonomyLifecycle, prof)
			return writeYAML(output, pack)
		},
	}
	addCompileFlags(cmd, &policyFile, &intentFile, &intentBaseDir, &adaptersDir, &profilesDir)
	cmd.Flags().StringVar(&target, "target", "", "TargetIntegrationProfile metadata.name (required)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default stdout)")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "default runtime action TTL (default depends on target mode)")
	cmd.Flags().StringArrayVar(&guardrailFiles, "guardrail", nil, "GuardrailPolicy YAML file to include in the RuntimePolicyPack (repeatable)")
	cmd.Flags().StringArrayVar(&detectionFiles, "detection", nil, "DetectionPolicy YAML file to include in the RuntimePolicyPack (repeatable)")
	cmd.Flags().StringArrayVar(&responseFiles, "response", nil, "ResponsePolicy YAML file to include in the RuntimePolicyPack (repeatable)")
	cmd.Flags().StringArrayVar(&alertRouteFiles, "alert-route", nil, "AlertRoute YAML file to include in the RuntimePolicyPack (repeatable)")
	return cmd
}

func buildRuntimeBundleCmd() *cobra.Command {
	var policyFile, intentFile, intentBaseDir, adaptersDir, profilesDir, target, output, signingKey, keyID, nodeID, mode, failover string
	var guardrailFiles []string
	var detectionFiles []string
	var responseFiles []string
	var alertRouteFiles []string
	var generation int
	var validFor, ttl time.Duration
	cmd := &cobra.Command{
		Use:   "build-runtime-bundle",
		Short: "Build and sign a KLIQ RuntimeBundle",
		RunE: func(cmd *cobra.Command, args []string) error {
			comp, plans, profiles, err := compilePlansFromInput(policyFile, intentFile, intentBaseDir, adaptersDir, profilesDir, guardrailFiles, detectionFiles, responseFiles, alertRouteFiles)
			if err != nil {
				return err
			}
			target = intentTargetOverride(comp, target)
			ep, prof, err := selectTarget(plans, profiles, target)
			if err != nil {
				return err
			}
			if err := validateRuntimeResponseReferences(comp.DetectionRules, comp.ResponseRules, comp.AlertRoutes); err != nil {
				return err
			}
			priv, err := signing.LoadPrivateKey(signingKey)
			if err != nil {
				return err
			}
			b, err := bundler.Build(ep, prof, bundler.BundleConfig{
				NodeID:            nodeID,
				Generation:        generation,
				IssuedAt:          time.Now().UTC(),
				ValidFor:          validFor,
				PreferredAdapters: []string{prof.Spec.AdapterRef},
				RuntimePDPMode:    mode,
				FailoverBehavior:  failover,
				DefaultTTL:        ttl,
				Guardrails:        comp.Guardrails,
				DetectionRules:    comp.DetectionRules,
				ResponseRules:     comp.ResponseRules,
				AlertRoutes:       comp.AlertRoutes,
				AutonomyLifecycle: comp.AutonomyLifecycle,
			}, priv)
			if err != nil {
				return err
			}
			emitRuntimePolicySupportWarnings(b.Spec.RuntimePolicyPack.Spec.AutonomyLifecycle, prof)
			if keyID != "" {
				b.Signature.KeyID = keyID
			}
			return writeYAML(output, b)
		},
	}
	addCompileFlags(cmd, &policyFile, &intentFile, &intentBaseDir, &adaptersDir, &profilesDir)
	cmd.Flags().StringVar(&target, "target", "", "TargetIntegrationProfile metadata.name (required)")
	cmd.Flags().StringVar(&nodeID, "node-id", "", "KLIQ node ID (required)")
	cmd.Flags().IntVar(&generation, "generation", 1, "bundle generation")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "PEM Ed25519 private key (required)")
	cmd.Flags().StringVar(&keyID, "key-id", "forge-runtime", "signature key ID")
	cmd.Flags().StringVar(&mode, "runtime-pdp-mode", "active", "runtime PDP mode encoded in bundle")
	cmd.Flags().StringVar(&failover, "failover", "fail_static", "offline failover behavior")
	cmd.Flags().DurationVar(&validFor, "valid-for", 24*time.Hour, "bundle validity duration")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "default runtime action TTL")
	cmd.Flags().StringArrayVar(&guardrailFiles, "guardrail", nil, "GuardrailPolicy YAML file to include in the RuntimeBundle policy pack (repeatable)")
	cmd.Flags().StringArrayVar(&detectionFiles, "detection", nil, "DetectionPolicy YAML file to include in the RuntimeBundle policy pack (repeatable)")
	cmd.Flags().StringArrayVar(&responseFiles, "response", nil, "ResponsePolicy YAML file to include in the RuntimeBundle policy pack (repeatable)")
	cmd.Flags().StringArrayVar(&alertRouteFiles, "alert-route", nil, "AlertRoute YAML file to include in the RuntimeBundle policy pack (repeatable)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default stdout)")
	_ = cmd.MarkFlagRequired("node-id")
	_ = cmd.MarkFlagRequired("signing-key")
	return cmd
}

func emitRuntimePolicySupportWarnings(lifecycle *contracts.RuntimeAutonomyLifecycleSpec, prof *profile.TargetIntegrationProfile) {
	for _, warning := range runtimePolicySupportWarnings(lifecycle, prof) {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}
}

func runtimePolicySupportWarnings(lifecycle *contracts.RuntimeAutonomyLifecycleSpec, prof *profile.TargetIntegrationProfile) []string {
	if lifecycle == nil {
		return nil
	}
	target := "<unknown>"
	if prof != nil && prof.Metadata.Name != "" {
		target = prof.Metadata.Name
	}
	var warnings []string
	if lifecycle.StepDown.CleanAfter.Duration > 0 || lifecycle.StepDown.ObserveAfter.Duration > 0 {
		warnings = append(warnings, "autonomy step_down is carried but not enforced by KLIQ runtime lifecycle yet")
	}
	if lifecycle.RestorePreviousOnResume {
		warnings = append(warnings, "autonomy restore_previous_on_resume is carried but not enforced by KLIQ cooldown lifecycle yet")
	}
	for _, allowance := range lifecycle.Allow {
		if prof != nil && allowance.Action != "" && !bundler.ProfileAllowsRuntimeCapability(prof, allowance.Action) {
			warnings = append(warnings, fmt.Sprintf("autonomy allowance action %s is not supported by target profile %q", allowance.Action, target))
		}
		if allowance.RequiresPreviousAction != "" && prof != nil && !bundler.ProfileAllowsRuntimeCapability(prof, allowance.RequiresPreviousAction) {
			warnings = append(warnings, fmt.Sprintf("autonomy allowance prerequisite %s is not supported by target profile %q", allowance.RequiresPreviousAction, target))
		}
	}
	for _, req := range lifecycle.ApprovalRequired {
		if prof != nil && req.Action != "" && !bundler.ProfileAllowsRuntimeCapability(prof, req.Action) {
			warnings = append(warnings, fmt.Sprintf("autonomy approval requirement action %s is not supported by target profile %q; it remains a deny-before-execute guard", req.Action, target))
		}
	}
	for _, limit := range lifecycle.MaxActionDuration {
		if prof != nil && limit.Action != "" && !bundler.ProfileAllowsRuntimeCapability(prof, limit.Action) {
			warnings = append(warnings, fmt.Sprintf("autonomy max duration action %s is not supported by target profile %q", limit.Action, target))
		}
	}
	for _, limit := range lifecycle.BlastRadius {
		warnings = append(warnings, fmt.Sprintf("autonomy blast-radius source-count limit for %s is carried but not enforced by broker counters yet", limit.Action))
	}
	return warnings
}

func configPDPCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config-pdp", Short: "Config PDP validation commands"}
	cmd.AddCommand(configPDPValidateCmd())
	return cmd
}

func configPDPValidateCmd() *cobra.Command {
	var policyFile, intentFile, intentBaseDir, adaptersDir, profilesDir, target, output string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate compiled target plan against AccessPolicy enforcementConstraints",
		RunE: func(cmd *cobra.Command, args []string) error {
			comp, plans, _, err := compilePlansFromInput(policyFile, intentFile, intentBaseDir, adaptersDir, profilesDir, nil, nil, nil, nil)
			if err != nil {
				return err
			}
			target = intentTargetOverride(comp, target)
			selected := plans
			if target != "" {
				p, _, err := selectTarget(plans, nil, target)
				if err != nil {
					return err
				}
				selected = []*plan.EnforcementPlan{p}
			}
			var reports []configpdp.ValidationReport
			deny := false
			for _, p := range selected {
				for _, access := range comp.AccessPolicies {
					r := configpdp.Validate(access, p)
					if r.Spec.Result == configpdp.ResultDeny {
						deny = true
					}
					reports = append(reports, r)
				}
			}
			if err := writeYAML(output, reports); err != nil {
				return err
			}
			if deny {
				return fmt.Errorf("config-pdp denied one or more target plans")
			}
			return nil
		},
	}
	addCompileFlags(cmd, &policyFile, &intentFile, &intentBaseDir, &adaptersDir, &profilesDir)
	cmd.Flags().StringVar(&target, "target", "", "optional TargetIntegrationProfile metadata.name")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default stdout)")
	return cmd
}

func reportCmd() *cobra.Command {
	var policyFile, intentFile, intentBaseDir, adaptersDir, profilesDir, output string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Emit coverage, delegation, downgrade and Config PDP reports",
		RunE: func(cmd *cobra.Command, args []string) error {
			comp, plans, _, err := compilePlansFromInput(policyFile, intentFile, intentBaseDir, adaptersDir, profilesDir, nil, nil, nil, nil)
			if err != nil {
				return err
			}
			validations := configPDPValidations(comp, plans)
			return writeYAML(output, report.Build(comp.SourceName(), plans, validations))
		},
	}
	addCompileFlags(cmd, &policyFile, &intentFile, &intentBaseDir, &adaptersDir, &profilesDir)
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default stdout)")
	return cmd
}

func keygenCmd() *cobra.Command {
	var privatePath, publicPath string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 keypair for signing runtime bundles",
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, priv, err := signing.GenerateKeyPair()
			if err != nil {
				return err
			}
			if privatePath == "" || publicPath == "" {
				return fmt.Errorf("--private and --public are required")
			}
			if err := signing.SavePrivateKey(privatePath, priv); err != nil {
				return err
			}
			if err := signing.SavePublicKey(publicPath, pub); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&privatePath, "private", "", "private key output path")
	cmd.Flags().StringVar(&publicPath, "public", "", "public key output path")
	return cmd
}

func conformanceFixturesCmd() *cobra.Command {
	var outputDir string
	cmd := &cobra.Command{
		Use:   "conformance-fixtures",
		Short: "Write KLIQ/Forge runtime contract conformance fixtures",
		RunE: func(cmd *cobra.Command, args []string) error {
			return conformancefixtures.Write(outputDir, time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC))
		},
	}
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "output directory")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func addCompileFlags(cmd *cobra.Command, policyFile, intentFile, intentBaseDir, adaptersDir, profilesDir *string) {
	cmd.Flags().StringVar(policyFile, "policy", "", "AccessPolicy YAML file")
	cmd.Flags().StringVar(intentFile, "intent", "", "PolicyIntent composition manifest YAML file")
	cmd.Flags().StringVar(intentBaseDir, "intent-base-dir", "", "base directory for relative PolicyIntent document refs (default: manifest directory)")
	cmd.Flags().StringVar(adaptersDir, "adapters", "", "directory of adapter subdirectories (required)")
	cmd.Flags().StringVar(profilesDir, "profiles", "", "directory of TargetIntegrationProfile YAML files (required)")
	_ = cmd.MarkFlagRequired("adapters")
	_ = cmd.MarkFlagRequired("profiles")
}

func compilePlans(policyFile, adaptersDir, profilesDir string) (*intent.AccessPolicy, []*plan.EnforcementPlan, []*profile.TargetIntegrationProfile, error) {
	comp, plans, profiles, err := compilePlansFromInput(policyFile, "", "", adaptersDir, profilesDir, nil, nil, nil, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	return comp.PrimaryAccessPolicy(), plans, profiles, nil
}

func configPDPValidations(comp *policyComposition, plans []*plan.EnforcementPlan) []configpdp.ValidationReport {
	if comp == nil {
		return nil
	}
	validations := make([]configpdp.ValidationReport, 0, len(comp.AccessPolicies)*len(plans))
	for _, p := range plans {
		for _, access := range comp.AccessPolicies {
			validations = append(validations, configpdp.Validate(access, p))
		}
	}
	return validations
}

func compilePlansFromInput(
	policyFile, intentFile, intentBaseDir, adaptersDir, profilesDir string,
	guardrailFiles, detectionFiles, responseFiles, alertRouteFiles []string,
) (*policyComposition, []*plan.EnforcementPlan, []*profile.TargetIntegrationProfile, error) {
	comp, err := loadPolicyComposition(intentFile, intentBaseDir, policyFile, guardrailFiles, detectionFiles, responseFiles, alertRouteFiles)
	if err != nil {
		return nil, nil, nil, err
	}
	profiles, err := loadProfiles(profilesDir)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("profiles: %w", err)
	}
	if len(profiles) == 0 {
		return nil, nil, nil, fmt.Errorf("no TargetIntegrationProfiles found in %s", profilesDir)
	}
	bundles, err := loadBundles(adaptersDir, profiles)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("adapters: %w", err)
	}
	plans, err := compileCompositionPlans(comp, profiles, bundles)
	if err != nil {
		return nil, nil, nil, err
	}
	applyCapabilityRequirementsToPlans(comp, plans, profiles)
	return comp, plans, profiles, nil
}

func compileCompositionPlans(comp *policyComposition, profiles []*profile.TargetIntegrationProfile, bundles map[string]*compiler.TargetBundle) ([]*plan.EnforcementPlan, error) {
	if comp == nil || len(comp.AccessPolicies) == 0 {
		return nil, fmt.Errorf("composition has no AccessPolicy")
	}
	multi := len(comp.AccessPolicies) > 1
	var compiled []*plan.EnforcementPlan
	for _, access := range comp.AccessPolicies {
		reqPolicies := requirementPoliciesForAccess(access, comp.RequirementPolicies)
		reqs, err := requirement.ExtractFromPolicies(access, reqPolicies)
		if err != nil {
			return nil, fmt.Errorf("requirement extraction for %s: %w", access.Metadata.Name, err)
		}
		unitPlans := compiler.Compile(access.Metadata.Name, reqs, profiles, bundles)
		if multi {
			prefixPlanRequirements(unitPlans, access.Metadata.Name)
		}
		compiled = append(compiled, unitPlans...)
	}
	if !multi {
		return compiled, nil
	}
	return mergeCompositionPlans(comp.SourceName(), compiled), nil
}

func requirementPoliciesForAccess(access *intent.AccessPolicy, policies []requirement.Policy) []requirement.Policy {
	if access == nil || len(access.Spec.Requirements) == 0 {
		return policies
	}
	wanted := map[string]bool{}
	for _, ref := range access.Spec.Requirements {
		ref = strings.TrimSpace(ref)
		if ref != "" {
			wanted[ref] = true
		}
	}
	var out []requirement.Policy
	for _, pol := range policies {
		if wanted[pol.Metadata.Name] {
			out = append(out, pol)
		}
	}
	return out
}

func prefixPlanRequirements(plans []*plan.EnforcementPlan, policyName string) {
	prefix := sanitizePlanID(policyName)
	if prefix == "" {
		prefix = "access"
	}
	for _, p := range plans {
		for i := range p.Spec.Requirements {
			p.Spec.Requirements[i].ID = prefix + "." + p.Spec.Requirements[i].ID
		}
		p.Spec.Summary.Delegation = prefixPlanIDs(p.Spec.Summary.Delegation, prefix)
		p.Spec.Summary.CompensatingControls = prefixPlanIDs(p.Spec.Summary.CompensatingControls, prefix)
		p.Spec.Summary.Downgrades = prefixPlanIDs(p.Spec.Summary.Downgrades, prefix)
		p.Spec.Summary.Unsupported = prefixPlanIDs(p.Spec.Summary.Unsupported, prefix)
	}
}

func prefixPlanIDs(ids []string, prefix string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, prefix+"."+id)
	}
	return out
}

func mergeCompositionPlans(sourceName string, plans []*plan.EnforcementPlan) []*plan.EnforcementPlan {
	byTarget := map[string]*plan.EnforcementPlan{}
	var targets []string
	for _, p := range plans {
		if p == nil {
			continue
		}
		target := p.Metadata.Target
		out := byTarget[target]
		if out == nil {
			clone := *p
			clone.Metadata.Name = sourceName + "-" + target
			clone.Metadata.SourcePolicy = sourceName
			clone.Spec.Requirements = nil
			clone.Spec.Summary = plan.PlanSummary{
				Deployable:       true,
				RuntimeModel:     p.Spec.Summary.RuntimeModel,
				SemanticFidelity: "high",
			}
			out = &clone
			byTarget[target] = out
			targets = append(targets, target)
		}
		out.Spec.Requirements = append(out.Spec.Requirements, p.Spec.Requirements...)
		mergePlanSummary(&out.Spec.Summary, p.Spec.Summary)
	}
	sort.Strings(targets)
	out := make([]*plan.EnforcementPlan, 0, len(targets))
	for _, target := range targets {
		p := byTarget[target]
		p.Spec.Summary.Deployable = len(p.Spec.Summary.Unsupported) == 0
		out = append(out, p)
	}
	return out
}

func mergePlanSummary(dst *plan.PlanSummary, src plan.PlanSummary) {
	if dst.RuntimeModel == "" {
		dst.RuntimeModel = src.RuntimeModel
	}
	dst.SemanticFidelity = lowerFidelity(dst.SemanticFidelity, src.SemanticFidelity)
	dst.Delegation = appendUniquePlanStrings(dst.Delegation, src.Delegation...)
	dst.CompensatingControls = appendUniquePlanStrings(dst.CompensatingControls, src.CompensatingControls...)
	dst.Downgrades = appendUniquePlanStrings(dst.Downgrades, src.Downgrades...)
	dst.Unsupported = appendUniquePlanStrings(dst.Unsupported, src.Unsupported...)
}

func lowerFidelity(a, b string) string {
	order := map[string]int{"none": 0, "": 0, "low": 1, "medium": 2, "high": 3}
	if order[b] < order[a] {
		return b
	}
	return a
}

func loadRuntimeGuardrails(paths []string) ([]contracts.RuntimeGuardrail, error) {
	var out []contracts.RuntimeGuardrail
	for _, path := range paths {
		p, err := guardrail.LoadPolicyFromFile(path)
		if err != nil {
			return nil, err
		}
		runtimeGuardrails, err := p.RuntimeGuardrails()
		if err != nil {
			return nil, fmt.Errorf("guardrail %s: %w", path, err)
		}
		out = append(out, runtimeGuardrails...)
	}
	return out, nil
}

func loadRuntimeResponseRules(paths []string) ([]contracts.RuntimeResponseRule, error) {
	var out []contracts.RuntimeResponseRule
	for _, path := range paths {
		p, err := response.LoadPolicyFromFile(path)
		if err != nil {
			return nil, err
		}
		rules, err := p.RuntimeResponseRules()
		if err != nil {
			return nil, fmt.Errorf("response %s: %w", path, err)
		}
		out = append(out, rules...)
	}
	return out, nil
}

func loadRuntimeDetectionRules(paths []string) ([]contracts.RuntimeDetectionRule, error) {
	var out []contracts.RuntimeDetectionRule
	for _, path := range paths {
		p, err := response.LoadDetectionPolicyFromFile(path)
		if err != nil {
			return nil, err
		}
		rules, err := p.RuntimeDetectionRules()
		if err != nil {
			return nil, fmt.Errorf("detection %s: %w", path, err)
		}
		out = append(out, rules...)
	}
	return out, nil
}

func loadRuntimeAlertRoutes(paths []string) ([]contracts.RuntimeAlertRoute, error) {
	var out []contracts.RuntimeAlertRoute
	for _, path := range paths {
		route, err := response.LoadAlertRouteFromFile(path)
		if err != nil {
			return nil, err
		}
		runtimeRoute, err := route.RuntimeAlertRoute()
		if err != nil {
			return nil, fmt.Errorf("alert route %s: %w", path, err)
		}
		out = append(out, runtimeRoute)
	}
	return out, nil
}

func validateRuntimeResponseReferences(detections []contracts.RuntimeDetectionRule, responses []contracts.RuntimeResponseRule, routes []contracts.RuntimeAlertRoute) error {
	snapshot, err := registries.EmbeddedSnapshot()
	if err != nil {
		return fmt.Errorf("load registry snapshot: %w", err)
	}
	if err := response.ValidateRuntimeReferences(detections, responses, routes, snapshot); err != nil {
		return fmt.Errorf("runtime response validation: %w", err)
	}
	return nil
}

func applyCapabilityRequirementsToPlans(comp *policyComposition, plans []*plan.EnforcementPlan, profiles []*profile.TargetIntegrationProfile) {
	if comp == nil || len(comp.CapabilityRequirements) == 0 || len(plans) == 0 {
		return
	}
	profilesByName := profilesByTargetName(profiles)
	for _, p := range plans {
		if p == nil {
			continue
		}
		prof := profilesByName[p.Metadata.Target]
		for _, req := range comp.CapabilityRequirements {
			requirementName := req.Metadata.Name
			if requirementName == "" {
				requirementName = req.Metadata.ID
			}
			if requirementName == "" {
				requirementName = "capability-requirement"
			}
			for _, item := range req.Spec.Required {
				applyCapabilityRequirementItem(p, prof, comp, requirementName, item)
			}
			for _, gap := range req.Spec.GapHandling {
				if isStrictGapBehavior(gap.Behavior) && planHasCapabilityGap(comp, p, gap.Gap) {
					markPlanCapabilityGap(p, "gap-"+gap.Gap, fmt.Sprintf("CapabilityRequirement %q requires %s on %s", requirementName, gap.Behavior, gap.Gap))
				}
			}
		}
	}
}

func applyCapabilityRequirementItem(p *plan.EnforcementPlan, prof *profile.TargetIntegrationProfile, comp *policyComposition, requirementName string, item requirement.CapabilityRequirementItem) {
	switch {
	case item.Context != "":
		if !planSupportsContext(p, item.Context) {
			markPlanCapabilityGap(p, "context-"+item.Context, fmt.Sprintf("CapabilityRequirement %q requires context %q for target %q", requirementName, item.Context, p.Metadata.Target))
		}
	case item.Capability != "":
		if !bundler.ProfileAllowsRuntimeCapability(prof, item.Capability) {
			markPlanCapabilityGap(p, "capability-"+item.Capability, fmt.Sprintf("CapabilityRequirement %q requires runtime capability %q for target %q", requirementName, item.Capability, p.Metadata.Target))
		}
	case item.Feature != "":
		applyFeatureRequirement(p, prof, comp, requirementName, item.Feature)
	}
	for _, granularity := range append(append([]string{}, item.Granularity.Subject...), item.Granularity.Resource...) {
		if granularity != "" && !planMentionsGranularity(p, granularity) {
			markPlanCapabilityGap(p, "granularity-"+granularity, fmt.Sprintf("CapabilityRequirement %q requires granularity %q for target %q", requirementName, granularity, p.Metadata.Target))
		}
	}
}

func applyFeatureRequirement(p *plan.EnforcementPlan, prof *profile.TargetIntegrationProfile, comp *policyComposition, requirementName, feature string) {
	switch strings.ReplaceAll(strings.ToLower(strings.TrimSpace(feature)), "-", "_") {
	case "identity_based_access":
		if planHasIdentityDowngrade(comp, p) {
			markPlanCapabilityGap(p, "identity-based-access", fmt.Sprintf("CapabilityRequirement %q requires identity-based access without identity-to-local downgrade", requirementName))
		}
	case "windowed_detection":
		if hasStatefulDetections(comp.DetectionRules) && (prof == nil || prof.Spec.Mode == profile.ModeConfigOnly) {
			markPlanCapabilityGap(p, "windowed-detection", fmt.Sprintf("CapabilityRequirement %q requires a runtime capable of windowed detection", requirementName))
		}
	case "traffic_rate_limit":
		if !bundler.ProfileAllowsRuntimeCapability(prof, "enforce.traffic.rate_limit") {
			markPlanCapabilityGap(p, "traffic-rate-limit", fmt.Sprintf("CapabilityRequirement %q requires traffic rate limiting", requirementName))
		}
	case "temporary_traffic_block", "temporary_block":
		if !bundler.ProfileAllowsRuntimeCapability(prof, "enforce.traffic.drop") {
			markPlanCapabilityGap(p, "temporary-traffic-block", fmt.Sprintf("CapabilityRequirement %q requires temporary traffic block", requirementName))
		}
	default:
		markPlanCapabilityGap(p, "feature-"+feature, fmt.Sprintf("CapabilityRequirement %q uses unsupported feature requirement %q", requirementName, feature))
	}
}

func planSupportsContext(p *plan.EnforcementPlan, key string) bool {
	if p == nil || key == "" {
		return false
	}
	for _, req := range p.Spec.Requirements {
		if strings.Contains(req.Requirement, key) {
			return req.Status != plan.StatusUnsupported
		}
	}
	return false
}

func planMentionsGranularity(p *plan.EnforcementPlan, granularity string) bool {
	if p == nil || granularity == "" {
		return false
	}
	needle := strings.ToLower(granularity)
	for _, req := range p.Spec.Requirements {
		if req.Downgrade != nil {
			text := strings.ToLower(req.Downgrade.From + " " + req.Downgrade.To + " " + req.Downgrade.Reason)
			if strings.Contains(text, needle) {
				return true
			}
		}
	}
	return false
}

func hasStatefulDetections(rules []contracts.RuntimeDetectionRule) bool {
	for _, rule := range rules {
		if rule.Window.Duration > 0 || rule.Threshold > 1 {
			return true
		}
		switch rule.Type {
		case "access.denied_threshold", "source.rate_limit_drops_sustained", "network.rate_limit_drop_threshold":
			return true
		}
	}
	return false
}

func planHasCapabilityGap(comp *policyComposition, p *plan.EnforcementPlan, gap string) bool {
	gap = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(gap)), "-", "_")
	switch gap {
	case "missing_context", "context_gap":
		for _, req := range p.Spec.Requirements {
			if req.RequirementKind == "capability_requirement" && strings.Contains(strings.Join(req.RuntimeNotes, " "), "requires context") {
				return true
			}
		}
	case "identity_to_ip_downgrade":
		return planHasIdentityDowngrade(comp, p)
	case "semantic_downgrade", "granularity_gap":
		return len(p.Spec.Summary.Downgrades) > 0
	case "enforcement_gap":
		for _, req := range p.Spec.Requirements {
			if req.RequirementKind == "capability_requirement" && strings.Contains(strings.Join(req.RuntimeNotes, " "), "runtime capability") {
				return true
			}
		}
	}
	return false
}

func planHasIdentityDowngrade(comp *policyComposition, p *plan.EnforcementPlan) bool {
	if p == nil {
		return false
	}
	if compositionAccessSubjectsAllAny(comp) {
		return false
	}
	for _, req := range p.Spec.Requirements {
		if req.RequirementKind == "subject_identity" && req.Status == plan.StatusPartial {
			return true
		}
		if req.RequirementKind != "subject_identity" {
			continue
		}
		if req.Downgrade == nil {
			continue
		}
		text := strings.ToLower(req.Downgrade.From + " " + req.Downgrade.To + " " + req.Downgrade.Reason)
		if strings.Contains(text, "identity") && (strings.Contains(text, "ip") || strings.Contains(text, "cgroup") || strings.Contains(text, "pid")) {
			return true
		}
	}
	return false
}

func compositionAccessSubjectsAllAny(comp *policyComposition) bool {
	if comp == nil || len(comp.AccessPolicies) == 0 {
		return false
	}
	for _, access := range comp.AccessPolicies {
		if access == nil || access.Spec.Subject.Type != "any" {
			return false
		}
	}
	return true
}

func isStrictGapBehavior(value string) bool {
	switch strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_") {
	case "fail", "fail_closed", "require_approval", "require_review":
		return true
	default:
		return false
	}
}

func markPlanCapabilityGap(p *plan.EnforcementPlan, id, note string) {
	if p == nil {
		return
	}
	id = "capability-requirement-" + sanitizePlanID(id)
	for _, existing := range p.Spec.Requirements {
		if existing.ID == id {
			return
		}
	}
	p.Spec.Requirements = append(p.Spec.Requirements, plan.RequirementEnforcement{
		ID:              id,
		RequirementKind: "capability_requirement",
		Requirement:     note,
		Status:          plan.StatusUnsupported,
		RuntimeNotes:    []string{note},
	})
	p.Spec.Summary.Deployable = false
	p.Spec.Summary.Unsupported = appendUniquePlanString(p.Spec.Summary.Unsupported, id)
}

func appendUniquePlanString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniquePlanStrings(values []string, newValues ...string) []string {
	for _, value := range newValues {
		values = appendUniquePlanString(values, value)
	}
	return values
}

func sanitizePlanID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var out strings.Builder
	lastDash := false
	for _, r := range value {
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

func selectTarget(plans []*plan.EnforcementPlan, profiles []*profile.TargetIntegrationProfile, target string) (*plan.EnforcementPlan, *profile.TargetIntegrationProfile, error) {
	var selectedPlan *plan.EnforcementPlan
	for _, p := range plans {
		if p.Metadata.Target == target {
			selectedPlan = p
			break
		}
	}
	if selectedPlan == nil {
		return nil, nil, fmt.Errorf("target %q not found", target)
	}
	var selectedProfile *profile.TargetIntegrationProfile
	for _, p := range profiles {
		if p.Metadata.Name == target {
			selectedProfile = p
			break
		}
	}
	if selectedProfile == nil && profiles != nil {
		return nil, nil, fmt.Errorf("profile %q not found", target)
	}
	return selectedPlan, selectedProfile, nil
}

func writeYAML(path string, v any) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	if path == "" || path == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func loadSigningKeyOrEphemeral(path string) (ed25519.PrivateKey, error) {
	if path != "" {
		return signing.LoadPrivateKey(path)
	}
	_, priv, err := signing.GenerateKeyPair()
	return priv, err
}
