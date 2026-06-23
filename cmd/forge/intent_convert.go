// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom-forge/pkg/core/guardrail"
	coreintent "github.com/kernloom/kernloom-forge/pkg/core/intent"
	"github.com/kernloom/kernloom-forge/pkg/core/naturalintent"
	"github.com/kernloom/kernloom-forge/pkg/core/requirement"
	"github.com/kernloom/kernloom-forge/pkg/core/response"
	registries "github.com/kernloom/kernloom-registries"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func intentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "intent",
		Short: "Convert natural policy intent into canonical policy YAML",
	}
	cmd.AddCommand(intentConvertCmd())
	cmd.AddCommand(intentSupportCmd())
	cmd.AddCommand(intentValidateCmd())
	return cmd
}

type naturalIntentSupportReport struct {
	APIVersion string                         `yaml:"apiVersion"`
	Kind       string                         `yaml:"kind"`
	Metadata   naturalIntentSupportReportMeta `yaml:"metadata"`
	Spec       naturalIntentSupportReportSpec `yaml:"spec"`
}

type naturalIntentSupportReportMeta struct {
	Name   string `yaml:"name,omitempty"`
	Target string `yaml:"target,omitempty"`
}

type naturalIntentSupportReportSpec struct {
	Summary     naturalIntentSupportSummary      `yaml:"summary"`
	Diagnostics []naturalIntentSupportDiagnostic `yaml:"diagnostics,omitempty"`
}

type naturalIntentSupportSummary struct {
	Enforced int `yaml:"enforced"`
	Carried  int `yaml:"carried"`
	Warnings int `yaml:"warnings"`
}

type naturalIntentSupportDiagnostic struct {
	Status  string `yaml:"status"`
	Line    int    `yaml:"line,omitempty"`
	Message string `yaml:"message"`
}

func intentConvertCmd() *cobra.Command {
	var input, output, outputDir, requirementsOutput, guardrailsOutput, detectionOutput, responseOutput, alertRouteOutput, capabilityOutput string
	var policyIntentOutput, compileTarget, name, owner, subjectType, resourceType string
	var emitPolicyIntent, showNotes bool

	cmd := &cobra.Command{
		Use:   "convert",
		Short: "Convert a natural .intent file into canonical policy YAML",
		Example: `  forge intent convert \
    --input examples/policies/protect-ziti-controller.intent \
    --output-dir /tmp/kernloom-forge-manual/policies \
    --emit-policy-intent \
    --owner security`,
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile(input)
			if err != nil {
				return err
			}
			if outputDir != "" {
				if err := os.MkdirAll(outputDir, 0o755); err != nil {
					return err
				}
				if !cmd.Flags().Changed("output") {
					output = filepath.Join(outputDir, "access.yaml")
				}
				if requirementsOutput == "" {
					requirementsOutput = filepath.Join(outputDir, "requirements.yaml")
				}
				if guardrailsOutput == "" {
					guardrailsOutput = filepath.Join(outputDir, "guardrails.yaml")
				}
				if detectionOutput == "" {
					detectionOutput = filepath.Join(outputDir, "detections.yaml")
				}
				if responseOutput == "" {
					responseOutput = filepath.Join(outputDir, "responses.yaml")
				}
				if capabilityOutput == "" {
					capabilityOutput = filepath.Join(outputDir, "capabilities.yaml")
				}
				if emitPolicyIntent && policyIntentOutput == "" {
					policyIntentOutput = filepath.Join(outputDir, "policy-intent.yaml")
				}
			}
			if policyIntentOutput != "" {
				emitPolicyIntent = true
			}
			result, err := naturalintent.Convert(raw, naturalintent.Options{
				Name:                name,
				Owner:               owner,
				DefaultSubjectType:  subjectType,
				DefaultResourceType: resourceType,
				EmitDetectionIR:     detectionOutput != "" || outputDir != "" || emitPolicyIntent,
			})
			if err != nil {
				return err
			}
			if showNotes {
				for _, note := range result.Notes {
					fmt.Fprintf(os.Stderr, "note: %s\n", note)
				}
			}
			for _, warning := range result.Warnings {
				fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
			}
			alertRoutes := mergeAlertRoutes(result.AlertRoutes, alertRoutesFromResponseRules(result.ResponseRules))
			if emitPolicyIntent {
				if policyIntentOutput == "" {
					return fmt.Errorf("--emit-policy-intent requires --output-dir or --policy-intent-output")
				}
				if output == "" || output == "-" {
					return fmt.Errorf("--emit-policy-intent requires AccessPolicy file output; set --output or --output-dir")
				}
				if len(result.Policy.Spec.Conditions) > 0 && requirementsOutput == "" {
					return fmt.Errorf("--emit-policy-intent requires --requirements-output or --output-dir for natural requirements")
				}
				if len(result.Guardrails) > 0 && guardrailsOutput == "" {
					return fmt.Errorf("--emit-policy-intent requires --guardrails-output or --output-dir for natural guardrails")
				}
				if len(result.DetectionRules) > 0 && detectionOutput == "" {
					return fmt.Errorf("--emit-policy-intent requires --detection-output or --output-dir for natural detection rules")
				}
				if len(result.ResponseRules) > 0 && responseOutput == "" {
					return fmt.Errorf("--emit-policy-intent requires --response-output or --output-dir for natural response rules")
				}
				if len(alertRoutes) > 0 && alertRouteOutput == "" && outputDir == "" {
					return fmt.Errorf("--emit-policy-intent requires --alert-route-output or --output-dir for alert response routes")
				}
				if len(result.Capabilities) > 0 && capabilityOutput == "" {
					return fmt.Errorf("--emit-policy-intent requires --capability-requirement-output or --output-dir for capability requirements")
				}
				if len(alertRoutes) > 1 && alertRouteOutput != "" {
					return fmt.Errorf("--alert-route-output supports one generated alert route; use --output-dir for multiple routes")
				}
			}
			var docs coreintent.PolicyIntentDocumentSet
			intentPath := policyIntentOutput
			if requirementsOutput != "" && len(result.Policy.Spec.Conditions) > 0 {
				requirementName := result.RequirementName
				if requirementName == "" {
					requirementName = result.Policy.Metadata.Name + "-requirements"
				}
				reqPolicy := requirement.PolicyFromConditions(requirementName, result.Policy.Metadata, result.Policy.Spec.Conditions)
				reqYAML, err := writeYAMLFile(requirementsOutput, reqPolicy)
				if err != nil {
					return err
				}
				docs.Requirements = append(docs.Requirements, policyIntentDocumentRef(intentPath, requirementsOutput, coreintent.PolicyKind(requirement.KindRequirementPolicy), requirementName, reqYAML))
			}
			if guardrailsOutput != "" && len(result.Guardrails) > 0 {
				guardrailName := name
				if guardrailName == "" {
					guardrailName = result.Policy.Metadata.Name + "-guardrails"
				}
				guardrailPolicy := guardrail.PolicyFromRuntime(guardrailName, result.Guardrails)
				guardrailYAML, err := writeYAMLFile(guardrailsOutput, guardrailPolicy)
				if err != nil {
					return err
				}
				docs.Guardrails = append(docs.Guardrails, policyIntentDocumentRef(intentPath, guardrailsOutput, guardrail.KindGuardrailPolicy, guardrailName, guardrailYAML))
			}
			if detectionOutput != "" && len(result.DetectionRules) > 0 {
				detectionName := name
				if detectionName == "" {
					detectionName = result.Policy.Metadata.Name + "-detections"
				}
				detectionPolicy := response.DetectionPolicyFromRuntime(detectionName, result.DetectionRules)
				detectionYAML, err := writeYAMLFile(detectionOutput, detectionPolicy)
				if err != nil {
					return err
				}
				docs.Detections = append(docs.Detections, policyIntentDocumentRef(intentPath, detectionOutput, response.KindDetectionPolicy, detectionName, detectionYAML))
			}
			if responseOutput != "" && len(result.ResponseRules) > 0 {
				responseName := name
				if responseName == "" {
					responseName = result.Policy.Metadata.Name + "-responses"
				}
				responsePolicy := response.PolicyFromRuntime(responseName, result.ResponseRules)
				responseYAML, err := writeYAMLFile(responseOutput, responsePolicy)
				if err != nil {
					return err
				}
				docs.Responses = append(docs.Responses, policyIntentDocumentRef(intentPath, responseOutput, response.KindResponsePolicy, responseName, responseYAML))
			}
			if alertRouteOutput != "" || outputDir != "" || emitPolicyIntent {
				for _, route := range alertRoutes {
					path := alertRouteOutput
					if path == "" {
						path = filepath.Join(outputDir, alertRouteFileName(route.ID))
					}
					routePolicy := response.AlertRouteFromRuntime(route)
					routeYAML, err := writeYAMLFile(path, routePolicy)
					if err != nil {
						return err
					}
					docs.AlertRoutes = append(docs.AlertRoutes, policyIntentDocumentRef(intentPath, path, response.KindAlertRoute, route.ID, routeYAML))
				}
			}
			if capabilityOutput != "" && len(result.Capabilities) > 0 {
				if len(result.Capabilities) > 1 && outputDir == "" {
					return fmt.Errorf("--capability-requirement-output supports one generated capability requirement; use --output-dir for multiple documents")
				}
				for i, capReq := range result.Capabilities {
					path := capabilityOutput
					if outputDir != "" && len(result.Capabilities) > 1 {
						path = filepath.Join(outputDir, capabilityRequirementFileName(capReq.Metadata.Name, i))
					}
					capYAML, err := writeYAMLFile(path, capReq)
					if err != nil {
						return err
					}
					docs.CapabilityRequirements = append(docs.CapabilityRequirements, policyIntentDocumentRef(intentPath, path, coreintent.PolicyKind("CapabilityRequirement"), capReq.Metadata.Name, capYAML))
				}
			}
			out, err := yaml.Marshal(result.Policy)
			if err != nil {
				return err
			}
			if output == "" || output == "-" {
				_, err = os.Stdout.Write(out)
				return err
			}
			if err := writeBytesFile(output, out); err != nil {
				return err
			}
			docs.Access = append(docs.Access, policyIntentDocumentRef(intentPath, output, coreintent.KindAccessPolicy, result.Policy.Metadata.Name, out))
			if !emitPolicyIntent {
				return nil
			}
			intentDoc := naturalPolicyIntent(input, result.Policy, docs, compileTarget, result.AutonomyLifecycle)
			intentYAML, err := yaml.Marshal(intentDoc)
			if err != nil {
				return err
			}
			return writeBytesFile(policyIntentOutput, intentYAML)
		},
	}

	cmd.Flags().StringVar(&input, "input", "", "natural policy intent file (required)")
	cmd.Flags().StringVar(&output, "output", "-", "AccessPolicy YAML output path, or '-' for stdout")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "directory for canonical AccessPolicy/GuardrailPolicy/DetectionPolicy/ResponsePolicy/AlertRoute outputs")
	cmd.Flags().StringVar(&requirementsOutput, "requirements-output", "", "optional RequirementPolicy YAML output path for natural require statements")
	cmd.Flags().StringVar(&guardrailsOutput, "guardrails-output", "", "optional GuardrailPolicy YAML output path for never/max action statements")
	cmd.Flags().StringVar(&detectionOutput, "detection-output", "", "optional DetectionPolicy YAML output path for when conditions")
	cmd.Flags().StringVar(&responseOutput, "response-output", "", "optional ResponsePolicy YAML output path for when/then response statements")
	cmd.Flags().StringVar(&alertRouteOutput, "alert-route-output", "", "optional AlertRoute YAML output path for natural alert actions")
	cmd.Flags().StringVar(&capabilityOutput, "capability-requirement-output", "", "optional CapabilityRequirement YAML output path for capabilities/gap handling blocks")
	cmd.Flags().BoolVar(&emitPolicyIntent, "emit-policy-intent", false, "emit a thin PolicyIntent manifest with digest-pinned references to generated canonical documents")
	cmd.Flags().BoolVar(&showNotes, "show-notes", false, "print informational conversion notes")
	cmd.Flags().StringVar(&policyIntentOutput, "policy-intent-output", "", "PolicyIntent YAML output path (implies --emit-policy-intent)")
	cmd.Flags().StringVar(&compileTarget, "compile-target", "", "optional PolicyIntent compile target")
	cmd.Flags().StringVar(&name, "name", "", "override metadata.name")
	cmd.Flags().StringVar(&owner, "owner", "", "metadata.owner")
	cmd.Flags().StringVar(&subjectType, "default-subject-type", "group", "selector type for untyped subjects")
	cmd.Flags().StringVar(&resourceType, "default-resource-type", "endpoint", "selector type for untyped resources")
	_ = cmd.MarkFlagRequired("input")
	return cmd
}

func intentSupportCmd() *cobra.Command {
	var input, output, target, name, owner, subjectType, resourceType string
	cmd := &cobra.Command{
		Use:   "support",
		Short: "Explain Natural Intent runtime support status",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile(input)
			if err != nil {
				return err
			}
			result, err := naturalintent.Convert(raw, naturalintent.Options{
				Name:                name,
				Owner:               owner,
				DefaultSubjectType:  subjectType,
				DefaultResourceType: resourceType,
				EmitDetectionIR:     true,
			})
			if err != nil {
				return err
			}
			report := buildNaturalIntentSupportReport(result, target)
			out, err := yaml.Marshal(report)
			if err != nil {
				return err
			}
			if output == "" || output == "-" {
				_, err = os.Stdout.Write(out)
				return err
			}
			return writeBytesFile(output, out)
		},
	}
	cmd.Flags().StringVar(&input, "input", "", "natural policy intent file (required)")
	cmd.Flags().StringVarP(&output, "output", "o", "-", "support report output path, or '-' for stdout")
	cmd.Flags().StringVar(&target, "target", "", "optional target adapter/profile name for report metadata")
	cmd.Flags().StringVar(&name, "name", "", "override metadata.name")
	cmd.Flags().StringVar(&owner, "owner", "", "metadata.owner")
	cmd.Flags().StringVar(&subjectType, "default-subject-type", "group", "selector type for untyped subjects")
	cmd.Flags().StringVar(&resourceType, "default-resource-type", "endpoint", "selector type for untyped resources")
	_ = cmd.MarkFlagRequired("input")
	return cmd
}

func buildNaturalIntentSupportReport(result *naturalintent.Result, target string) naturalIntentSupportReport {
	report := naturalIntentSupportReport{
		APIVersion: "kernloom.io/v1",
		Kind:       "NaturalIntentSupportReport",
		Metadata: naturalIntentSupportReportMeta{
			Target: target,
		},
	}
	if result != nil && result.Policy != nil {
		report.Metadata.Name = result.Policy.Metadata.Name
	}
	if result == nil {
		return report
	}
	for _, note := range result.Notes {
		diag := naturalIntentDiagnosticFromMessage(note)
		report.Spec.Diagnostics = append(report.Spec.Diagnostics, diag)
		switch diag.Status {
		case "enforced":
			report.Spec.Summary.Enforced++
		case "carried":
			report.Spec.Summary.Carried++
		case "warning":
			report.Spec.Summary.Warnings++
		}
	}
	for _, warning := range result.Warnings {
		diag := naturalIntentDiagnosticFromMessage(warning)
		diag.Status = "warning"
		report.Spec.Diagnostics = append(report.Spec.Diagnostics, diag)
		report.Spec.Summary.Warnings++
	}
	return report
}

func naturalIntentDiagnosticFromMessage(message string) naturalIntentSupportDiagnostic {
	line, rest := supportLinePrefix(message)
	status := "carried"
	switch {
	case strings.Contains(rest, "ENFORCED"):
		status = "enforced"
	case strings.Contains(rest, "WARNING"):
		status = "warning"
	case strings.Contains(rest, "CARRIED"):
		status = "carried"
	}
	return naturalIntentSupportDiagnostic{
		Status:  status,
		Line:    line,
		Message: strings.TrimSpace(rest),
	}
}

func supportLinePrefix(message string) (int, string) {
	message = strings.TrimSpace(message)
	if !strings.HasPrefix(message, "line ") {
		return 0, message
	}
	rest := strings.TrimPrefix(message, "line ")
	colon := strings.Index(rest, ":")
	if colon <= 0 {
		return 0, message
	}
	line, err := strconv.Atoi(strings.TrimSpace(rest[:colon]))
	if err != nil {
		return 0, message
	}
	return line, strings.TrimSpace(rest[colon+1:])
}

func naturalPolicyIntent(input string, policy *coreintent.AccessPolicy, docs coreintent.PolicyIntentDocumentSet, compileTarget string, autonomyLifecycle *contracts.RuntimeAutonomyLifecycleSpec) coreintent.PolicyIntent {
	return coreintent.PolicyIntent{
		APIVersion: "kernloom.io/v1",
		Kind:       coreintent.KindPolicyIntent,
		Metadata: coreintent.PolicyMetadata{
			Name:        policy.Metadata.Name + "-intent",
			Owner:       policy.Metadata.Owner,
			Environment: policy.Metadata.Environment,
		},
		Spec: coreintent.PolicyIntentSpec{
			Description: "Generated from " + filepath.Base(input) + ".",
			Protect: coreintent.PolicyIntentProtect{
				Resource:    policy.Spec.Resource.Ref,
				Environment: policy.Metadata.Environment,
			},
			Documents:  docs,
			Registries: policyIntentRegistryPins(),
			Runtime: coreintent.PolicyIntentRuntime{
				AutonomyLifecycle: autonomyLifecycle,
			},
			Compile: coreintent.PolicyIntentCompileTarget{
				Target: compileTarget,
			},
		},
	}
}

func policyIntentRegistryPins() coreintent.PolicyIntentRegistryPins {
	snapshot, err := registries.EmbeddedSnapshot()
	if err != nil {
		return coreintent.PolicyIntentRegistryPins{}
	}
	pin := coreintent.PolicyIntentRegistryPin{
		Name:    snapshot.Ref.Name,
		Version: snapshot.Ref.Version,
		Digest:  snapshot.Ref.Digest,
	}
	return coreintent.PolicyIntentRegistryPins{
		Context:                 pin,
		Actions:                 pin,
		Capabilities:            pin,
		Granularity:             pin,
		DetectionEvaluators:     pin,
		MissingContextBehaviors: pin,
		Guardrails:              pin,
		GapHandling:             pin,
		Notifications:           pin,
		Snapshot:                pin,
	}
}

func writeYAMLFile(path string, value any) ([]byte, error) {
	raw, err := yaml.Marshal(value)
	if err != nil {
		return nil, err
	}
	return raw, writeBytesFile(path, raw)
}

func writeBytesFile(path string, raw []byte) error {
	if path == "" || path == "-" {
		return fmt.Errorf("file output path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func policyIntentDocumentRef(intentPath, documentPath string, kind coreintent.PolicyKind, name string, raw []byte) coreintent.PolicyIntentDocumentRef {
	ref := documentPath
	if intentPath != "" {
		if rel, err := filepath.Rel(filepath.Dir(intentPath), documentPath); err == nil {
			ref = rel
		}
	}
	sum := sha256.Sum256(raw)
	return coreintent.PolicyIntentDocumentRef{
		Kind:   kind,
		Name:   name,
		Ref:    filepath.ToSlash(ref),
		Digest: "sha256:" + hex.EncodeToString(sum[:]),
	}
}

func alertRoutesFromResponseRules(rules []contracts.RuntimeResponseRule) []contracts.RuntimeAlertRoute {
	routes := map[string]contracts.RuntimeAlertRoute{}
	for _, rule := range rules {
		for _, action := range rule.Then {
			if action.ID != "notify.alert.emit" || action.Route == "" {
				continue
			}
			if _, ok := routes[action.Route]; ok {
				continue
			}
			severity := action.Severity
			if severity == "" {
				severity = "medium"
			}
			dedupe := action.Dedupe
			if dedupe.Duration <= 0 {
				dedupe = contracts.NewDuration(15 * time.Minute)
			}
			short := strings.TrimPrefix(action.Route, "alert-route.")
			audienceRef := "group." + short
			if short == "security-ops" {
				audienceRef = "group.kernloom-security-ops"
			}
			routes[action.Route] = contracts.RuntimeAlertRoute{
				ID: action.Route,
				Audience: contracts.RuntimeAlertAudience{
					Type: "group",
					Ref:  audienceRef,
				},
				Channels: []contracts.RuntimeAlertChannel{
					{Type: "log", Ref: "log." + short},
					{Type: "email", Ref: "channel." + short},
				},
				DefaultSeverity: severity,
				Deduplication: contracts.RuntimeAlertDeduplication{
					Enabled: true,
					Window:  dedupe,
					Keys:    []string{"resource.id", "detection.id", "source.identity_or_ip"},
				},
				CaseManagement: contracts.RuntimeAlertCaseManagement{
					CreateCase: boolParam(action.Params, "create_case"),
				},
			}
		}
	}
	ids := make([]string, 0, len(routes))
	for id := range routes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]contracts.RuntimeAlertRoute, 0, len(ids))
	for _, id := range ids {
		out = append(out, routes[id])
	}
	return out
}

func mergeAlertRoutes(primary, fallback []contracts.RuntimeAlertRoute) []contracts.RuntimeAlertRoute {
	routes := map[string]contracts.RuntimeAlertRoute{}
	for _, route := range fallback {
		if route.ID != "" {
			routes[route.ID] = route
		}
	}
	for _, route := range primary {
		if route.ID != "" {
			routes[route.ID] = mergeAlertRoute(route, routes[route.ID])
		}
	}
	ids := make([]string, 0, len(routes))
	for id := range routes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]contracts.RuntimeAlertRoute, 0, len(ids))
	for _, id := range ids {
		out = append(out, routes[id])
	}
	return out
}

func mergeAlertRoute(primary, fallback contracts.RuntimeAlertRoute) contracts.RuntimeAlertRoute {
	out := fallback
	if out.ID == "" {
		out.ID = primary.ID
	}
	if primary.Audience.Type != "" || primary.Audience.Ref != "" {
		out.Audience = primary.Audience
	}
	if len(primary.Channels) > 0 {
		out.Channels = append([]contracts.RuntimeAlertChannel(nil), primary.Channels...)
	}
	if primary.DefaultSeverity != "" {
		out.DefaultSeverity = primary.DefaultSeverity
	}
	if primary.Deduplication.Enabled {
		out.Deduplication.Enabled = true
	}
	if primary.Deduplication.Window.Duration > 0 {
		out.Deduplication.Window = primary.Deduplication.Window
	}
	if len(primary.Deduplication.Keys) > 0 {
		out.Deduplication.Keys = append([]string(nil), primary.Deduplication.Keys...)
	}
	if primary.CaseManagement.CreateCase {
		out.CaseManagement.CreateCase = true
	}
	if primary.Acknowledgement.Required {
		out.Acknowledgement = primary.Acknowledgement
	}
	return out
}

func boolParam(params map[string]any, key string) bool {
	value, ok := params[key]
	if !ok {
		return false
	}
	b, _ := value.(bool)
	return b
}

func alertRouteFileName(routeID string) string {
	routeID = strings.TrimPrefix(routeID, "alert-route.")
	return fileNameSlug(routeID) + "-alert-route.yaml"
}

func capabilityRequirementFileName(name string, index int) string {
	if strings.TrimSpace(name) == "" {
		name = fmt.Sprintf("capabilities-%d", index+1)
	}
	return fileNameSlug(name) + ".yaml"
}

func fileNameSlug(value string) string {
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
	slug := strings.Trim(out.String(), "-")
	if slug == "" {
		return "alert-route"
	}
	return slug
}

func intentValidateCmd() *cobra.Command {
	var input, baseDir string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a PolicyIntent composition manifest and referenced policy documents",
		RunE: func(cmd *cobra.Command, args []string) error {
			if baseDir == "" {
				baseDir = filepath.Dir(input)
			}
			comp, err := loadPolicyCompositionFromIntent(input, baseDir)
			if err != nil {
				return err
			}
			fmt.Printf("OK: PolicyIntent %q is valid (%d detection, %d response, %d alert route runtime item(s))\n",
				comp.Intent.Metadata.Name, len(comp.DetectionRules), len(comp.ResponseRules), len(comp.AlertRoutes))
			return nil
		},
	}

	cmd.Flags().StringVar(&input, "input", "", "PolicyIntent YAML file (required)")
	cmd.Flags().StringVar(&baseDir, "base-dir", "", "base directory for relative document refs (default: input directory)")
	_ = cmd.MarkFlagRequired("input")
	return cmd
}

func policyIntentSections(docs coreintent.PolicyIntentDocumentSet) map[string][]coreintent.PolicyIntentDocumentRef {
	return map[string][]coreintent.PolicyIntentDocumentRef{
		"access":                 docs.Access,
		"requirements":           docs.Requirements,
		"detections":             docs.Detections,
		"responses":              docs.Responses,
		"alertRoutes":            docs.AlertRoutes,
		"guardrails":             docs.Guardrails,
		"capabilityRequirements": docs.CapabilityRequirements,
	}
}

func resolvePolicyIntentRef(baseDir, ref string) string {
	if ref == "" || filepath.IsAbs(ref) {
		return ref
	}
	return filepath.Join(baseDir, ref)
}
