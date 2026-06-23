// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom-forge/pkg/core/guardrail"
	coreintent "github.com/kernloom/kernloom-forge/pkg/core/intent"
	"github.com/kernloom/kernloom-forge/pkg/core/requirement"
	"github.com/kernloom/kernloom-forge/pkg/core/response"
	registries "github.com/kernloom/kernloom-registries"
	"gopkg.in/yaml.v3"
)

type policyComposition struct {
	Intent                 *coreintent.PolicyIntent
	IntentBaseDir          string
	AccessPolicy           *coreintent.AccessPolicy
	AccessPolicies         []*coreintent.AccessPolicy
	AccessPath             string
	AccessPaths            []string
	RequirementPolicies    []requirement.Policy
	CapabilityRequirements []requirement.CapabilityRequirement
	Guardrails             []contracts.RuntimeGuardrail
	DetectionRules         []contracts.RuntimeDetectionRule
	ResponseRules          []contracts.RuntimeResponseRule
	AlertRoutes            []contracts.RuntimeAlertRoute
	AutonomyLifecycle      *contracts.RuntimeAutonomyLifecycleSpec
}

type documentHeader struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name    string `yaml:"name,omitempty"`
		ID      string `yaml:"id,omitempty"`
		Version string `yaml:"version,omitempty"`
	} `yaml:"metadata"`
}

func loadPolicyComposition(
	intentFile string,
	intentBaseDir string,
	policyFile string,
	guardrailFiles []string,
	detectionFiles []string,
	responseFiles []string,
	alertRouteFiles []string,
) (*policyComposition, error) {
	if intentFile != "" {
		if policyFile != "" || len(guardrailFiles) > 0 || len(detectionFiles) > 0 || len(responseFiles) > 0 || len(alertRouteFiles) > 0 {
			return nil, fmt.Errorf("--intent cannot be mixed with --policy, --guardrail, --detection, --response or --alert-route")
		}
		return loadPolicyCompositionFromIntent(intentFile, intentBaseDir)
	}
	if policyFile == "" {
		return nil, fmt.Errorf("either --policy or --intent is required")
	}
	pol, err := coreintent.LoadAccessPolicyFromFile(policyFile)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	guardrails, err := loadRuntimeGuardrails(guardrailFiles)
	if err != nil {
		return nil, err
	}
	detectionRules, err := loadRuntimeDetectionRules(detectionFiles)
	if err != nil {
		return nil, err
	}
	responseRules, err := loadRuntimeResponseRules(responseFiles)
	if err != nil {
		return nil, err
	}
	alertRoutes, err := loadRuntimeAlertRoutes(alertRouteFiles)
	if err != nil {
		return nil, err
	}
	return &policyComposition{
		AccessPolicy:   pol,
		AccessPolicies: []*coreintent.AccessPolicy{pol},
		AccessPath:     policyFile,
		AccessPaths:    []string{policyFile},
		Guardrails:     guardrails,
		DetectionRules: detectionRules,
		ResponseRules:  responseRules,
		AlertRoutes:    alertRoutes,
	}, nil
}

func loadPolicyCompositionFromIntent(path, baseDir string) (*policyComposition, error) {
	intentDoc, err := coreintent.LoadPolicyIntentFromFile(path)
	if err != nil {
		return nil, err
	}
	if err := validatePolicyIntentRegistryPins(intentDoc); err != nil {
		return nil, err
	}
	if baseDir == "" {
		baseDir = filepath.Dir(path)
	}
	out := &policyComposition{
		Intent:            intentDoc,
		IntentBaseDir:     baseDir,
		AutonomyLifecycle: intentDoc.Spec.Runtime.AutonomyLifecycle,
	}
	for section, refs := range policyIntentSections(intentDoc.Spec.Documents) {
		for i, ref := range refs {
			resolved := resolvePolicyIntentRef(baseDir, ref.Path())
			header, err := validatePolicyIntentDocumentRef(section, i, resolved, ref)
			if err != nil {
				return nil, err
			}
			switch section {
			case "access":
				pol, err := coreintent.LoadAccessPolicyFromFile(resolved)
				if err != nil {
					return nil, fmt.Errorf("PolicyIntent %s %s: %w", section, resolved, err)
				}
				if out.AccessPolicy == nil {
					out.AccessPolicy = pol
					out.AccessPath = resolved
				}
				out.AccessPolicies = append(out.AccessPolicies, pol)
				out.AccessPaths = append(out.AccessPaths, resolved)
			case "requirements":
				pol, err := requirement.LoadPolicyFromFile(resolved)
				if err != nil {
					return nil, fmt.Errorf("PolicyIntent %s %s: %w", section, resolved, err)
				}
				out.RequirementPolicies = append(out.RequirementPolicies, *pol)
			case "guardrails":
				pol, err := guardrail.LoadPolicyFromFile(resolved)
				if err != nil {
					return nil, fmt.Errorf("PolicyIntent %s %s: %w", section, resolved, err)
				}
				rules, err := pol.RuntimeGuardrails()
				if err != nil {
					return nil, fmt.Errorf("PolicyIntent %s %s: %w", section, resolved, err)
				}
				out.Guardrails = append(out.Guardrails, rules...)
			case "detections":
				pol, err := response.LoadDetectionPolicyFromFile(resolved)
				if err != nil {
					return nil, fmt.Errorf("PolicyIntent %s %s: %w", section, resolved, err)
				}
				rules, err := pol.RuntimeDetectionRules()
				if err != nil {
					return nil, fmt.Errorf("PolicyIntent %s %s: %w", section, resolved, err)
				}
				out.DetectionRules = append(out.DetectionRules, rules...)
			case "responses":
				pol, err := response.LoadPolicyFromFile(resolved)
				if err != nil {
					return nil, fmt.Errorf("PolicyIntent %s %s: %w", section, resolved, err)
				}
				rules, err := pol.RuntimeResponseRules()
				if err != nil {
					return nil, fmt.Errorf("PolicyIntent %s %s: %w", section, resolved, err)
				}
				out.ResponseRules = append(out.ResponseRules, rules...)
			case "alertRoutes":
				route, err := response.LoadAlertRouteFromFile(resolved)
				if err != nil {
					return nil, fmt.Errorf("PolicyIntent %s %s: %w", section, resolved, err)
				}
				runtimeRoute, err := route.RuntimeAlertRoute()
				if err != nil {
					return nil, fmt.Errorf("PolicyIntent %s %s: %w", section, resolved, err)
				}
				out.AlertRoutes = append(out.AlertRoutes, runtimeRoute)
			case "capabilityRequirements":
				req, err := requirement.LoadCapabilityRequirementFromFile(resolved)
				if err != nil {
					return nil, fmt.Errorf("PolicyIntent %s %s: %w", section, resolved, err)
				}
				out.CapabilityRequirements = append(out.CapabilityRequirements, *req)
			default:
				if header.Kind == "" {
					return nil, fmt.Errorf("PolicyIntent %s %s has no kind", section, resolved)
				}
			}
		}
	}
	if len(out.AccessPolicies) == 0 {
		return nil, fmt.Errorf("PolicyIntent must reference at least one AccessPolicy")
	}
	if err := validateRuntimeResponseReferences(out.DetectionRules, out.ResponseRules, out.AlertRoutes); err != nil {
		return nil, err
	}
	return out, nil
}

func (comp *policyComposition) SourceName() string {
	if comp == nil {
		return ""
	}
	if comp.Intent != nil && comp.Intent.Metadata.Name != "" {
		return comp.Intent.Metadata.Name
	}
	if comp.AccessPolicy != nil {
		return comp.AccessPolicy.Metadata.Name
	}
	return "policy-composition"
}

func (comp *policyComposition) PrimaryAccessPolicy() *coreintent.AccessPolicy {
	if comp == nil {
		return nil
	}
	if comp.AccessPolicy != nil {
		return comp.AccessPolicy
	}
	if len(comp.AccessPolicies) > 0 {
		return comp.AccessPolicies[0]
	}
	return nil
}

func validatePolicyIntentRegistryPins(intentDoc *coreintent.PolicyIntent) error {
	if intentDoc == nil {
		return nil
	}
	snapshot, err := registries.EmbeddedSnapshot()
	if err != nil {
		return fmt.Errorf("PolicyIntent registry pin validation: %w", err)
	}
	for name, pin := range intentDoc.Spec.Registries.ByName() {
		if pin.Name == "" && pin.Version == "" && pin.Digest == "" {
			continue
		}
		if pin.Name != "" && pin.Name != snapshot.Ref.Name {
			return fmt.Errorf("PolicyIntent registry pin %s name mismatch: got %q want %q", name, pin.Name, snapshot.Ref.Name)
		}
		if pin.Version != "" && pin.Version != snapshot.Ref.Version {
			return fmt.Errorf("PolicyIntent registry pin %s version mismatch: got %q want %q", name, pin.Version, snapshot.Ref.Version)
		}
		if pin.Digest != "" && pin.Digest != snapshot.Ref.Digest {
			return fmt.Errorf("PolicyIntent registry pin %s digest mismatch: got %s want %s", name, snapshot.Ref.Digest, pin.Digest)
		}
	}
	return nil
}

func validatePolicyIntentDocumentRef(section string, index int, path string, ref coreintent.PolicyIntentDocumentRef) (*documentHeader, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("PolicyIntent %s %s: %w", section, path, err)
	}
	if ref.Digest != "" {
		got := sha256.Sum256(raw)
		gotRef := "sha256:" + hex.EncodeToString(got[:])
		if gotRef != ref.Digest {
			return nil, fmt.Errorf("PolicyIntent %s[%d] %s digest mismatch: got %s, want %s", section, index, path, gotRef, ref.Digest)
		}
	}
	var header documentHeader
	if err := yaml.Unmarshal(raw, &header); err != nil {
		return nil, fmt.Errorf("PolicyIntent %s %s: parse header: %w", section, path, err)
	}
	if header.Kind == "" {
		return nil, fmt.Errorf("PolicyIntent %s %s has no kind", section, path)
	}
	expectedKind := expectedPolicyIntentKind(section)
	if ref.Kind != "" {
		expectedKind = ref.Kind
	}
	if expectedKind != "" && header.Kind != expectedKind {
		return nil, fmt.Errorf("PolicyIntent %s[%d] %s kind mismatch: got %s, want %s", section, index, path, header.Kind, expectedKind)
	}
	if ref.Name != "" && header.Metadata.Name != ref.Name && header.Metadata.ID != ref.Name {
		return nil, fmt.Errorf("PolicyIntent %s[%d] %s name mismatch: got %q/%q, want %q", section, index, path, header.Metadata.Name, header.Metadata.ID, ref.Name)
	}
	if ref.Version != "" && header.Metadata.Version != ref.Version {
		return nil, fmt.Errorf("PolicyIntent %s[%d] %s version mismatch: got %q, want %q", section, index, path, header.Metadata.Version, ref.Version)
	}
	return &header, nil
}

func expectedPolicyIntentKind(section string) string {
	switch section {
	case "access":
		return coreintent.KindAccessPolicy
	case "guardrails":
		return guardrail.KindGuardrailPolicy
	case "detections":
		return response.KindDetectionPolicy
	case "responses":
		return response.KindResponsePolicy
	case "alertRoutes":
		return response.KindAlertRoute
	case "requirements":
		return "RequirementPolicy"
	case "capabilityRequirements":
		return "CapabilityRequirement"
	default:
		return ""
	}
}

func intentTargetOverride(comp *policyComposition, explicitTarget string) string {
	if explicitTarget != "" {
		return explicitTarget
	}
	if comp != nil && comp.Intent != nil {
		return comp.Intent.Spec.Compile.Target
	}
	return ""
}
