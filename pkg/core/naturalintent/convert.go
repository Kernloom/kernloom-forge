// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package naturalintent converts a small human-friendly policy intent syntax
// into canonical AccessPolicy YAML objects.
package naturalintent

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom-forge/pkg/core/guardrail"
	"github.com/kernloom/kernloom-forge/pkg/core/intent"
	registries "github.com/kernloom/kernloom-registries"
)

type Options struct {
	Name                string
	Owner               string
	DefaultSubjectType  string
	DefaultResourceType string
	EmitDetectionIR     bool
}

type Result struct {
	Policy            *intent.AccessPolicy
	RequirementName   string
	Guardrails        []contracts.RuntimeGuardrail
	DetectionRules    []contracts.RuntimeDetectionRule
	ResponseRules     []contracts.RuntimeResponseRule
	AlertRoutes       []contracts.RuntimeAlertRoute
	AutonomyLifecycle *contracts.RuntimeAutonomyLifecycleSpec
	Capabilities      []CapabilityRequirement
	Notes             []string
	Warnings          []string
}

type CapabilityRequirement struct {
	APIVersion string                    `yaml:"apiVersion"`
	Kind       string                    `yaml:"kind"`
	Metadata   CapabilityRequirementMeta `yaml:"metadata"`
	Spec       CapabilityRequirementSpec `yaml:"spec"`
}

type CapabilityRequirementMeta struct {
	Name string `yaml:"name,omitempty"`
}

type CapabilityRequirementSpec struct {
	Required    []CapabilityRequirementItem `yaml:"required,omitempty"`
	GapHandling []GapHandlingRule           `yaml:"gapHandling,omitempty"`
}

type CapabilityRequirementItem struct {
	Capability string `yaml:"capability,omitempty"`
	Context    string `yaml:"context,omitempty"`
	Feature    string `yaml:"feature,omitempty"`
}

type GapHandlingRule struct {
	Behavior string `yaml:"behavior"`
	Gap      string `yaml:"gap"`
}

func Convert(data []byte, opts Options) (*Result, error) {
	if opts.DefaultSubjectType == "" {
		opts.DefaultSubjectType = "group"
	}
	if opts.DefaultResourceType == "" {
		opts.DefaultResourceType = "endpoint"
	}
	registry, err := loadNaturalRegistry()
	if err != nil {
		return nil, err
	}

	var (
		intentName        string
		resourceType      string
		resourceRef       string
		subjectType       string
		subjectRef        string
		environment       string
		conditions        []intent.Condition
		conditionIDs      map[string]int
		requirementName   string
		guardrails        []contracts.RuntimeGuardrail
		detections        []contracts.RuntimeDetectionRule
		detectionIDs      map[string]bool
		responses         []contracts.RuntimeResponseRule
		routeDefinitions  map[string]*alertRouteDefinition
		autonomyLifecycle *contracts.RuntimeAutonomyLifecycleSpec
		capabilities      []CapabilityRequirement
		activeCapability  *CapabilityRequirement
		notes             []string
		warnings          []string
	)
	conditionIDs = map[string]int{}
	detectionIDs = map[string]bool{}
	routeDefinitions = map[string]*alertRouteDefinition{}
	state := naturalSectionState{}
	lastResponseIndex := -1

	lines, err := parseNaturalSourceLines(data)
	if err != nil {
		return nil, err
	}
	for _, line := range lines {
		tokens := line.Tokens
		if len(tokens) >= 2 && tokens[0] == "intent" {
			intentName = tokens[1]
			state = naturalSectionState{}
			continue
		}
		if section, name, ok := naturalSectionHeader(tokens); ok {
			state = naturalSectionState{Kind: section, Name: name}
			if section == "alert_route" {
				state.AlertRouteID = normalizeAlertRoute(name)
				if state.AlertRouteID == "" {
					return nil, fmt.Errorf("line %d: alert_route requires a name", line.No)
				}
				ensureAlertRouteDefinition(routeDefinitions, state.AlertRouteID)
			}
			if section == "requirements" && requirementName == "" {
				requirementName = strings.TrimSpace(name)
			}
			if section == "capabilities" {
				name = strings.TrimSpace(name)
				if name == "" {
					name = "capabilities"
				}
				capabilities = append(capabilities, CapabilityRequirement{
					APIVersion: "kernloom.io/v1",
					Kind:       "CapabilityRequirement",
					Metadata:   CapabilityRequirementMeta{Name: name},
				})
				activeCapability = &capabilities[len(capabilities)-1]
			}
			continue
		}

		switch state.Kind {
		case "compose":
			continue
		case "detection":
			if trimColon(tokens[0]) == "detect" {
				if len(tokens) < 2 {
					return nil, fmt.Errorf("line %d: detect requires an id", line.No)
				}
				state.DetectionID = trimColon(tokens[1])
				continue
			}
			if tokens[0] == "when" {
				detectionRule, err := parseDetectionStatement(tokens[1:], state.DetectionID, resourceRef)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", line.No, err)
				}
				if err := validateDetectionRule(registry, detectionRule); err != nil {
					return nil, fmt.Errorf("line %d: %w", line.No, err)
				}
				if !detectionIDs[detectionRule.ID] {
					detections = append(detections, detectionRule)
					detectionIDs[detectionRule.ID] = true
				}
				notes = append(notes, fmt.Sprintf("line %d: detection %q is emitted as DetectionPolicy IR, not into AccessPolicy", line.No, detectionRule.ID))
				continue
			}
		case "response":
			if tokens[0] == "on" {
				responseRule, err := parseOnResponse(tokens[1:])
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", line.No, err)
				}
				responses = append(responses, responseRule)
				lastResponseIndex = len(responses) - 1
				notes = append(notes, fmt.Sprintf("line %d: ENFORCED response rule %q is emitted as ResponsePolicy IR for RuntimePDP/KLIQ", line.No, responseRule.ID))
				warnings = append(warnings, responseRuleWarnings(line.No, responseRule)...)
				continue
			}
			if tokens[0] == "require" && lastResponseIndex >= 0 {
				note, warning, err := applyResponseRequirement(&responses[lastResponseIndex], tokens[1:])
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", line.No, err)
				}
				if note != "" {
					notes = append(notes, fmt.Sprintf("line %d: %s", line.No, note))
				}
				if warning != "" {
					warnings = append(warnings, fmt.Sprintf("line %d: %s", line.No, warning))
				}
				continue
			}
			if tokens[0] == "allow" && lastResponseIndex >= 0 {
				note, err := applyResponseAllowance(&responses[lastResponseIndex], tokens[1:])
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", line.No, err)
				}
				if note != "" {
					notes = append(notes, fmt.Sprintf("line %d: %s", line.No, note))
				}
				continue
			}
		case "autonomy":
			note, warning, err := applyAutonomyLine(&autonomyLifecycle, tokens)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line.No, err)
			}
			if note != "" {
				notes = append(notes, fmt.Sprintf("line %d: %s", line.No, note))
			}
			if warning != "" {
				warnings = append(warnings, fmt.Sprintf("line %d: %s", line.No, warning))
			}
			continue
		case "alert_route":
			if err := applyAlertRouteLine(routeDefinitions, state.AlertRouteID, tokens); err != nil {
				return nil, fmt.Errorf("line %d: %w", line.No, err)
			}
			continue
		case "capabilities":
			if activeCapability != nil {
				if err := applyCapabilityRequirementLine(activeCapability, tokens); err != nil {
					return nil, fmt.Errorf("line %d: %w", line.No, err)
				}
				continue
			}
		case "gap_handling":
			if len(capabilities) == 0 {
				capabilities = append(capabilities, CapabilityRequirement{
					APIVersion: "kernloom.io/v1",
					Kind:       "CapabilityRequirement",
					Metadata:   CapabilityRequirementMeta{Name: "gap-handling"},
				})
			}
			activeCapability = &capabilities[len(capabilities)-1]
			if err := applyGapHandlingLine(activeCapability, tokens); err != nil {
				return nil, fmt.Errorf("line %d: %w", line.No, err)
			}
			continue
		}

		switch tokens[0] {
		case "protect":
			protectTokens, _ := splitOptionalAs(tokens[1:])
			refTokens, envTokens := splitOptionalIn(protectTokens)
			if len(refTokens) == 0 {
				return nil, fmt.Errorf("line %d: protect requires a resource", line.No)
			}
			resourceType, resourceRef = parseResource(refTokens, opts.DefaultResourceType)
			if len(envTokens) > 0 {
				environment = strings.Join(envTokens, " ")
			}
		case "allow":
			subjTokens, resTokens, err := splitAccessStatement(tokens[1:])
			if err != nil {
				if !isAllowAll(tokens[1:]) {
					return nil, fmt.Errorf("line %d: %w", line.No, err)
				}
				subjTokens = tokens[1:]
			}
			subjectType, subjectRef = parseSubject(subjTokens, opts.DefaultSubjectType)
			if len(resTokens) > 0 {
				resourceType, resourceRef = parseResource(resTokens, opts.DefaultResourceType)
			}
		case "require":
			condition, err := parseRequire(tokens[1:])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line.No, err)
			}
			if err := validateCondition(registry, condition); err != nil {
				return nil, fmt.Errorf("line %d: %w", line.No, err)
			}
			condition.ID = uniqueConditionID(conditionIDs, "require-"+slug(condition.Signal))
			conditions = append(conditions, condition)
		case "deny":
			warnings = append(warnings, fmt.Sprintf("line %d: deny statements are not emitted yet; use target default deny or RuntimePolicyPack default_effect", line.No))
		case "default":
			if len(tokens) >= 2 && tokens[1] == "deny" {
				warnings = append(warnings, fmt.Sprintf("line %d: default deny is represented later as target default behavior or RuntimePolicyPack default_effect", line.No))
				continue
			}
			return nil, fmt.Errorf("line %d: unsupported default statement %q", line.No, line.Text)
		case "when":
			rule, err := parseWhen(tokens[1:])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line.No, err)
			}
			if !rule.IsZero() {
				runtimeRule := rule.RuntimeRule()
				if opts.EmitDetectionIR {
					detectionRule := rule.DetectionRule()
					if err := validateDetectionRule(registry, detectionRule); err != nil {
						return nil, fmt.Errorf("line %d: %w", line.No, err)
					}
					if !detectionIDs[detectionRule.ID] {
						detections = append(detections, detectionRule)
						detectionIDs[detectionRule.ID] = true
					}
					runtimeRule = rule.RuntimeRuleForDetection(detectionRule.ID)
				}
				responses = append(responses, runtimeRule)
				action := runtimeRule.Then[0]
				note := fmt.Sprintf("line %d: response rule %q is emitted as ResponsePolicy IR, not into AccessPolicy", line.No, runtimeRule.ID)
				if opts.EmitDetectionIR {
					note = fmt.Sprintf("line %d: detection %q and response rule %q are emitted as DetectionPolicy/ResponsePolicy IR, not into AccessPolicy", line.No, runtimeRule.When.Detection, runtimeRule.ID)
				}
				if action.ID == "notify.alert.emit" {
					note += fmt.Sprintf(" (alert route %q severity %q dedupe %s)", action.Route, action.Severity, action.Dedupe)
				}
				notes = append(notes, note)
				warnings = append(warnings, responseRuleWarnings(line.No, runtimeRule)...)
				continue
			}
			warnings = append(warnings, fmt.Sprintf("line %d: when/then response rules are not emitted into AccessPolicy yet", line.No))
		case "never":
			g, err := guardrail.FromNeverTokens(tokens[1:])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line.No, err)
			}
			guardrails = append(guardrails, g)
			notes = append(notes, fmt.Sprintf("line %d: never guardrail %q is emitted as runtime guardrail, not into AccessPolicy", line.No, g.ID))
		case "max":
			if len(tokens) >= 2 && tokens[1] == "action" {
				warnings = append(warnings, fmt.Sprintf("line %d: max action guardrails are not emitted into AccessPolicy yet", line.No))
				continue
			}
			return nil, fmt.Errorf("line %d: unsupported max statement %q", line.No, line.Text)
		case "unless":
			warnings = append(warnings, fmt.Sprintf("line %d: unless exceptions are not emitted into AccessPolicy yet", line.No))
		default:
			return nil, fmt.Errorf("line %d: unsupported statement %q", line.No, tokens[0])
		}
	}

	applyAlertRouteDefinitions(responses, routeDefinitions)
	alertRoutes := runtimeAlertRoutesFromDefinitions(routeDefinitions)
	if resourceRef == "" {
		return nil, fmt.Errorf("intent must contain a protected or accessed resource")
	}
	if subjectType == "" {
		subjectType = "any"
	}

	name := opts.Name
	if name == "" {
		name = intentName
	}
	if name == "" {
		name = "protect-" + slug(resourceRef)
	}

	pol := &intent.AccessPolicy{
		APIVersion: "kernloom.io/v1",
		Kind:       intent.KindAccessPolicy,
		Metadata: intent.PolicyMetadata{
			Name:        name,
			Owner:       opts.Owner,
			Environment: environment,
		},
		Spec: intent.AccessPolicySpec{
			Subject: intent.Subject{
				Type: subjectType,
				Ref:  subjectRef,
			},
			Action: "access",
			Resource: intent.Resource{
				Type: resourceType,
				Ref:  resourceRef,
			},
			Conditions: conditions,
			Effect:     "allow",
		},
	}
	if requirementName != "" {
		pol.Spec.Requirements = []string{requirementName}
	}
	if err := pol.Validate(); err != nil {
		return nil, err
	}
	return &Result{
		Policy:            pol,
		RequirementName:   requirementName,
		Guardrails:        guardrails,
		DetectionRules:    detections,
		ResponseRules:     responses,
		AlertRoutes:       alertRoutes,
		AutonomyLifecycle: autonomyLifecycle,
		Capabilities:      capabilities,
		Notes:             notes,
		Warnings:          warnings,
	}, nil
}

type naturalSourceLine struct {
	No     int
	Indent int
	Text   string
	Tokens []string
}

type naturalSectionState struct {
	Kind         string
	Name         string
	DetectionID  string
	AlertRouteID string
}

type naturalRegistry struct {
	ContextKeys map[string]contracts.ContextKeyEntry
	Signals     map[string]bool
}

type alertRouteDefinition struct {
	ID              string
	Audience        contracts.RuntimeAlertAudience
	Channels        []contracts.RuntimeAlertChannel
	DefaultSeverity string
	DedupeKeys      []string
	CreateCase      *bool
	AckRequired     bool
	AckTimeout      time.Duration
	Escalations     []contracts.RuntimeAlertEscalation
}

func parseNaturalSourceLines(data []byte) ([]naturalSourceLine, error) {
	var out []naturalSourceLine
	for lineNo, raw := range strings.Split(string(data), "\n") {
		indent := leadingSpaces(raw)
		line := stripComment(strings.TrimSpace(raw))
		if line == "" {
			continue
		}
		tokens, err := tokenize(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo+1, err)
		}
		if len(tokens) == 0 {
			continue
		}
		out = append(out, naturalSourceLine{
			No:     lineNo + 1,
			Indent: indent,
			Text:   line,
			Tokens: tokens,
		})
	}
	return out, nil
}

func leadingSpaces(raw string) int {
	n := 0
	for _, r := range raw {
		if r != ' ' && r != '\t' {
			return n
		}
		n++
	}
	return n
}

func naturalSectionHeader(tokens []string) (string, string, bool) {
	if len(tokens) == 0 || !lineHasTrailingColon(tokens) {
		return "", "", false
	}
	head := trimColon(tokens[0])
	switch head {
	case "compose":
		return "compose", "", true
	case "access", "requirements", "detection", "response", "autonomy", "guardrail", "alert_route", "capabilities":
		return head, trimColon(strings.Join(tokens[1:], " ")), true
	case "gap_handling":
		return head, "", true
	default:
		return "", "", false
	}
}

func lineHasTrailingColon(tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	last := tokens[len(tokens)-1]
	return last == ":" || strings.HasSuffix(last, ":")
}

func trimColon(value string) string {
	return strings.TrimSuffix(strings.TrimSpace(value), ":")
}

func loadNaturalRegistry() (naturalRegistry, error) {
	snapshot, err := registries.EmbeddedSnapshot()
	if err != nil {
		return naturalRegistry{}, fmt.Errorf("load registry snapshot: %w", err)
	}
	reg := naturalRegistry{
		ContextKeys: map[string]contracts.ContextKeyEntry{},
		Signals:     map[string]bool{},
	}
	for _, key := range snapshot.ContextKeys {
		reg.ContextKeys[key.ID] = key
	}
	for _, signal := range snapshot.Signals {
		reg.Signals[signal.ID] = true
	}
	return reg, nil
}

func validateCondition(reg naturalRegistry, condition intent.Condition) error {
	key, ok := reg.ContextKeys[condition.Signal]
	if !ok {
		return fmt.Errorf("unknown context key %q", condition.Signal)
	}
	return validateConditionValue(key, condition.Operator, condition.Value)
}

func validateDetectionRule(reg naturalRegistry, rule contracts.RuntimeDetectionRule) error {
	switch rule.Type {
	case responseRuleMetricThreshold:
		key := stringParam(rule.Params, "key", "signal", "metric")
		if key == "" {
			return fmt.Errorf("metric.threshold detection %q requires params.key", rule.ID)
		}
		if contextKey, ok := reg.ContextKeys[key]; ok {
			return validateConditionValue(contextKey, stringParam(rule.Params, "operator", "op"), rule.Params["value"])
		}
		if reg.Signals[key] {
			return nil
		}
		return fmt.Errorf("unknown detection key %q", key)
	case "signal.threshold", "signal.score_threshold":
		signalID := stringParam(rule.Params, "signal_type", "type")
		if signalID == "" {
			return fmt.Errorf("signal detection %q requires params.signal_type", rule.ID)
		}
		if !reg.Signals[signalID] {
			return fmt.Errorf("unknown signal %q", signalID)
		}
	}
	return nil
}

func validateConditionValue(key contracts.ContextKeyEntry, operator string, value any) error {
	if len(key.Values) == 0 {
		return nil
	}
	allowed := map[string]bool{}
	for _, v := range key.Values {
		allowed[v] = true
	}
	for _, v := range valueStrings(value) {
		if !allowed[v] {
			return fmt.Errorf("value %q is not allowed for context key %q", v, key.ID)
		}
	}
	return nil
}

func valueStrings(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return []string{fmt.Sprint(typed)}
	}
}

func stringParam(params map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := params[key]; ok {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}

const (
	responseRuleDeniedAccess     = "access.denied_threshold"
	responseRuleMetricThreshold  = "metric.threshold"
	responseRuleDefaultThreshold = 1
)

type responseRule struct {
	Type        string
	ResourceRef string
	Signal      string
	Operator    string
	Value       any
	Params      map[string]any
	Threshold   int
	Window      time.Duration
	Action      contracts.RuntimeResponseAction
}

func (r responseRule) IsZero() bool {
	return r.Type == "" || r.Action.ID == ""
}

func (r responseRule) RuntimeRule() contracts.RuntimeResponseRule {
	actionSlug := slug(r.Action.ID)
	if r.Action.Route != "" {
		actionSlug = slug(r.Action.Route)
	}
	return contracts.RuntimeResponseRule{
		ID:          r.responseID(actionSlug),
		When:        r.runtimeTrigger(),
		Then:        []contracts.RuntimeResponseAction{r.Action},
		ReasonCodes: r.reasonCodes(),
	}
}

func (r responseRule) RuntimeRuleForDetection(detectionID string) contracts.RuntimeResponseRule {
	actionSlug := slug(r.Action.ID)
	if r.Action.Route != "" {
		actionSlug = slug(r.Action.Route)
	}
	return contracts.RuntimeResponseRule{
		ID: "on-" + slug(detectionID) + "-" + actionSlug,
		When: contracts.RuntimeResponseTrigger{
			Detection: detectionID,
		},
		Then: []contracts.RuntimeResponseAction{r.Action},
		ReasonCodes: []string{
			"response_on_" + strings.ReplaceAll(slug(detectionID), "-", "_"),
		},
	}
}

func (r responseRule) DetectionRule() contracts.RuntimeDetectionRule {
	rule := contracts.RuntimeDetectionRule{
		ID:          r.detectionID(),
		Type:        r.Type,
		ResourceRef: r.ResourceRef,
		Threshold:   r.Threshold,
		Window:      contracts.NewDuration(r.Window),
		Scope:       "source",
		ReasonCodes: r.reasonCodes(),
		Params:      detectionRuntimeParams(nil, true),
	}
	if r.Type == responseRuleMetricThreshold {
		rule.Threshold = responseRuleDefaultThreshold
		rule.Params = detectionRuntimeParams(r.conditionParams(), false)
	}
	if r.Type == "signal.threshold" || r.Type == "signal.score_threshold" {
		rule.Threshold = responseRuleDefaultThreshold
		rule.Params = detectionRuntimeParams(r.conditionParams(), false)
	}
	return rule
}

func (r responseRule) runtimeTrigger() contracts.RuntimeResponseTrigger {
	trigger := contracts.RuntimeResponseTrigger{
		Type:        r.Type,
		ResourceRef: r.ResourceRef,
		Threshold:   r.Threshold,
		Window:      contracts.NewDuration(r.Window),
	}
	if r.Type == responseRuleMetricThreshold {
		trigger.Threshold = responseRuleDefaultThreshold
		trigger.Scope = "source"
		trigger.Params = r.conditionParams()
	}
	if r.Type == "signal.threshold" || r.Type == "signal.score_threshold" {
		trigger.Threshold = responseRuleDefaultThreshold
		trigger.Scope = "source"
		trigger.Params = r.conditionParams()
	}
	return trigger
}

func (r responseRule) conditionParams() map[string]any {
	if len(r.Params) > 0 {
		out := make(map[string]any, len(r.Params))
		for k, v := range r.Params {
			out[k] = v
		}
		return out
	}
	params := map[string]any{
		"key":      r.Signal,
		"operator": r.Operator,
		"value":    r.Value,
	}
	if r.Signal != "" {
		params["signal"] = r.Signal
	}
	return params
}

func (r responseRule) responseID(actionSlug string) string {
	if r.Type == responseRuleMetricThreshold {
		return "signal-" + slug(r.Signal) + "-" + slug(r.Operator) + "-" + slug(valueString(r.Value)) + "-" + actionSlug
	}
	if r.Type == "signal.threshold" || r.Type == "signal.score_threshold" {
		return "signal-" + slug(r.Signal) + "-" + actionSlug
	}
	return "denied-access-" + slug(r.ResourceRef) + "-" + actionSlug
}

func (r responseRule) reasonCodes() []string {
	if r.Type == responseRuleMetricThreshold {
		return []string{
			"signal_condition_matched",
			"signal_" + strings.ReplaceAll(slug(r.Signal), "-", "_"),
		}
	}
	if r.Type == "signal.threshold" || r.Type == "signal.score_threshold" {
		return []string{
			"signal_observed",
			"signal_" + strings.ReplaceAll(slug(r.Signal), "-", "_"),
		}
	}
	return []string{
		"denied_access_threshold_exceeded",
	}
}

func (r responseRule) detectionID() string {
	if r.Type == responseRuleMetricThreshold {
		return "signal-" + slug(r.Signal) + "-" + slug(r.Operator) + "-" + slug(valueString(r.Value))
	}
	if r.Type == "signal.threshold" || r.Type == "signal.score_threshold" {
		return "signal-" + slug(r.Signal)
	}
	return "denied-access-" + slug(r.ResourceRef) + "-exceeds-" + strconv.Itoa(r.Threshold) + "-within-" + slug(r.Window.String())
}

func valueString(value any) string {
	switch typed := value.(type) {
	case []string:
		return strings.Join(typed, "-")
	default:
		return fmt.Sprint(typed)
	}
}

func deniedAccessDetectionRule(resourceRef string, threshold int, window time.Duration) contracts.RuntimeDetectionRule {
	return contracts.RuntimeDetectionRule{
		ID:          "denied-access-" + slug(resourceRef) + "-exceeds-" + strconv.Itoa(threshold) + "-within-" + slug(window.String()),
		Type:        responseRuleDeniedAccess,
		ResourceRef: resourceRef,
		Threshold:   threshold,
		Window:      contracts.NewDuration(window),
		Scope:       "source",
		Params:      detectionRuntimeParams(nil, true),
		ReasonCodes: []string{
			"denied_access_threshold_exceeded",
		},
	}
}

func detectionRuntimeParams(params map[string]any, stateRequired bool) map[string]any {
	out := map[string]any{}
	for k, v := range params {
		out[k] = v
	}
	out["group_by"] = []string{"source.identity_or_ip"}
	out["missing_context"] = "not_match"
	if stateRequired {
		out["evaluator_type"] = "windowed"
		out["evaluator_state_required"] = true
		out["allowed_runtimes"] = []string{"kliq-local-windowed", "correlate"}
		return out
	}
	out["evaluator_type"] = "stateless"
	out["evaluator_state_required"] = false
	out["allowed_runtimes"] = []string{"kliq-local-stateless", "correlate"}
	return out
}

func detectionResourceRef(tokens []string) string {
	_, ref := parseResource(tokens, "")
	return ref
}

func parseWhen(tokens []string) (responseRule, error) {
	if len(tokens) == 0 {
		return responseRule{}, fmt.Errorf("when requires a condition")
	}
	if len(tokens) < 3 || tokens[0] != "denied" || tokens[1] != "access" || tokens[2] != "to" {
		return parseSignalWhen(tokens)
	}
	if len(tokens) < 10 {
		return responseRule{}, fmt.Errorf("when denied access must use 'denied access to <resource> exceeds <count> within <duration> then <action>'")
	}

	exceedsIndex := indexToken(tokens, "exceeds")
	if exceedsIndex <= 3 {
		return responseRule{}, fmt.Errorf("when denied access requires a resource before exceeds")
	}
	if exceedsIndex+4 >= len(tokens) {
		return responseRule{}, fmt.Errorf("when denied access must use 'exceeds <count> within <duration> then <action>'")
	}

	threshold, err := strconv.Atoi(tokens[exceedsIndex+1])
	if err != nil || threshold <= 0 {
		return responseRule{}, fmt.Errorf("when denied access exceeds value must be a positive integer")
	}
	if tokens[exceedsIndex+2] != "within" {
		return responseRule{}, fmt.Errorf("when denied access must use 'within <duration>' after exceeds")
	}
	window := tokens[exceedsIndex+3]
	windowDuration, err := parseDurationToken(window)
	if err != nil {
		return responseRule{}, fmt.Errorf("when denied access window: %w", err)
	}
	thenIndex := exceedsIndex + 4
	if tokens[thenIndex] != "then" {
		return responseRule{}, fmt.Errorf("when denied access must use then before the action")
	}

	actionTokens := tokens[thenIndex+1:]
	if len(actionTokens) == 0 {
		return responseRule{}, fmt.Errorf("when denied access then requires an action")
	}
	action, err := parseResponseAction(actionTokens)
	if err != nil {
		return responseRule{}, err
	}

	return responseRule{
		Type:        responseRuleDeniedAccess,
		ResourceRef: detectionResourceRef(tokens[3:exceedsIndex]),
		Threshold:   threshold,
		Window:      windowDuration,
		Action:      action,
	}, nil
}

func parseSignalWhen(tokens []string) (responseRule, error) {
	if len(tokens) >= 2 && tokens[0] == "signal" {
		return parseSignalEventWhen(tokens)
	}
	thenIndex := indexToken(tokens, "then")
	if thenIndex < 0 {
		return responseRule{}, nil
	}
	if thenIndex == 0 {
		return responseRule{}, fmt.Errorf("when requires a condition before then")
	}
	if thenIndex == len(tokens)-1 {
		return responseRule{}, fmt.Errorf("when then requires an action")
	}
	conditionTokens := expandNaturalConditionTokens(tokens[:thenIndex])
	opIndex := -1
	for i, tok := range conditionTokens {
		if isOperator(tok) {
			opIndex = i
			break
		}
	}
	if opIndex <= 0 {
		return responseRule{}, fmt.Errorf("when signal condition must use '<signal> <operator> <value> then <action>'")
	}
	if opIndex == len(conditionTokens)-1 {
		return responseRule{}, fmt.Errorf("when signal condition is missing a value")
	}
	signal := normalizeSignal(conditionTokens[:opIndex])
	if signal == "" {
		return responseRule{}, fmt.Errorf("when signal condition is missing a signal")
	}
	operator := normalizeOperator(conditionTokens[opIndex])
	value := parseConditionValue(operator, conditionTokens[opIndex+1:])
	action, err := parseResponseAction(tokens[thenIndex+1:])
	if err != nil {
		return responseRule{}, err
	}
	return responseRule{
		Type:      responseRuleMetricThreshold,
		Signal:    signal,
		Operator:  operator,
		Value:     value,
		Threshold: responseRuleDefaultThreshold,
		Action:    action,
	}, nil
}

func parseSignalEventWhen(tokens []string) (responseRule, error) {
	thenIndex := indexToken(tokens, "then")
	if thenIndex < 0 {
		return responseRule{}, fmt.Errorf("when signal must use 'then <action>'")
	}
	if len(tokens) < 3 || thenIndex == len(tokens)-1 {
		return responseRule{}, fmt.Errorf("when signal must use 'signal <id> then <action>'")
	}
	signalID := tokens[1]
	params := map[string]any{"signal_type": signalID}
	if thenIndex > 2 {
		if thenIndex != 5 || tokens[2] != "score" || !isOperator(tokens[3]) {
			return responseRule{}, fmt.Errorf("when signal supports optional 'score <operator> <number>' before then")
		}
		operator := normalizeOperator(tokens[3])
		if operator != "gte" && operator != "gt" {
			return responseRule{}, fmt.Errorf("when signal score currently supports gt/gte")
		}
		score, err := strconv.ParseFloat(tokens[4], 64)
		if err != nil {
			return responseRule{}, fmt.Errorf("when signal score must be numeric")
		}
		params["min_score"] = score
	}
	action, err := parseResponseAction(tokens[thenIndex+1:])
	if err != nil {
		return responseRule{}, err
	}
	return responseRule{
		Type:      "signal.threshold",
		Signal:    signalID,
		Params:    params,
		Threshold: responseRuleDefaultThreshold,
		Action:    action,
	}, nil
}

func parseDetectionStatement(tokens []string, explicitID, fallbackResource string) (contracts.RuntimeDetectionRule, error) {
	if len(tokens) == 0 {
		return contracts.RuntimeDetectionRule{}, fmt.Errorf("detect when requires a condition")
	}
	if len(tokens) >= 3 && tokens[0] == "denied" && tokens[1] == "access" && tokens[2] == "to" {
		return parseDeniedAccessDetection(tokens, explicitID)
	}
	if len(tokens) >= 2 && tokens[0] == "rate_limit" && tokens[1] == "drops" {
		return parseRateLimitDropsDetection(tokens, explicitID, fallbackResource)
	}
	if len(tokens) >= 2 && tokens[0] == "signal" {
		return parseSignalDetection(tokens, explicitID)
	}
	return parseConditionDetection(tokens, explicitID)
}

func parseDeniedAccessDetection(tokens []string, explicitID string) (contracts.RuntimeDetectionRule, error) {
	exceedsIndex := indexToken(tokens, "exceeds")
	if exceedsIndex <= 3 {
		return contracts.RuntimeDetectionRule{}, fmt.Errorf("denied access detection requires a resource before exceeds")
	}
	if exceedsIndex+3 >= len(tokens) {
		return contracts.RuntimeDetectionRule{}, fmt.Errorf("denied access detection must use 'exceeds <count> within <duration>'")
	}
	byIndex := indexTokenBefore(tokens, "by", exceedsIndex)
	resourceEnd := exceedsIndex
	var selectorTokens []string
	if byIndex > 3 {
		resourceEnd = byIndex
		selectorTokens = tokens[byIndex+1 : exceedsIndex]
	}
	resource := detectionResourceRef(tokens[3:resourceEnd])
	threshold, err := strconv.Atoi(tokens[exceedsIndex+1])
	if err != nil || threshold <= 0 {
		return contracts.RuntimeDetectionRule{}, fmt.Errorf("denied access exceeds value must be a positive integer")
	}
	if tokens[exceedsIndex+2] != "within" {
		return contracts.RuntimeDetectionRule{}, fmt.Errorf("denied access detection must use within <duration>")
	}
	window, err := parseDurationToken(tokens[exceedsIndex+3])
	if err != nil {
		return contracts.RuntimeDetectionRule{}, fmt.Errorf("denied access window: %w", err)
	}
	rule := deniedAccessDetectionRule(resource, threshold, window)
	if explicitID != "" {
		rule.ID = explicitID
	}
	subject, params, reason, err := parseDetectionSubjectSelector(selectorTokens)
	if err != nil {
		return contracts.RuntimeDetectionRule{}, err
	}
	rule.Subject = subject
	if len(params) > 0 {
		rule.Params = detectionRuntimeParams(params, true)
	}
	if reason != "" {
		rule.ReasonCodes = append(rule.ReasonCodes, reason)
	}
	return rule, nil
}

func parseRateLimitDropsDetection(tokens []string, explicitID, fallbackResource string) (contracts.RuntimeDetectionRule, error) {
	toIndex := indexToken(tokens, "to")
	sustainedIndex := indexToken(tokens, "sustained")
	if sustainedIndex < 0 {
		return contracts.RuntimeDetectionRule{}, fmt.Errorf("rate_limit drops detection must use sustained for <duration>")
	}
	if sustainedIndex+2 >= len(tokens) || tokens[sustainedIndex+1] != "for" {
		return contracts.RuntimeDetectionRule{}, fmt.Errorf("rate_limit drops detection must use sustained for <duration>")
	}
	window, err := parseDurationToken(tokens[sustainedIndex+2])
	if err != nil {
		return contracts.RuntimeDetectionRule{}, fmt.Errorf("rate_limit drops sustained window: %w", err)
	}
	resource := fallbackResource
	bySearchStart := 2
	if toIndex >= 0 && toIndex < sustainedIndex {
		bySearchStart = toIndex + 1
		byIndex := indexTokenRange(tokens, "by", bySearchStart, sustainedIndex)
		resourceEnd := sustainedIndex
		if byIndex >= 0 {
			resourceEnd = byIndex
		}
		if resourceEnd > toIndex+1 {
			resource = detectionResourceRef(tokens[toIndex+1 : resourceEnd])
		}
	}
	byIndex := indexTokenRange(tokens, "by", bySearchStart, sustainedIndex)
	var selectorTokens []string
	if byIndex >= 0 {
		selectorTokens = tokens[byIndex+1 : sustainedIndex]
	}
	subject, params, reason, err := parseDetectionSubjectSelector(selectorTokens)
	if err != nil {
		return contracts.RuntimeDetectionRule{}, err
	}
	id := explicitID
	if id == "" {
		id = "rate-limit-drops-" + slug(resource) + "-sustained-" + slug(window.String())
	}
	reasons := []string{"rate_limit_drops_sustained"}
	if reason != "" {
		reasons = append(reasons, reason)
	}
	return contracts.RuntimeDetectionRule{
		ID:          id,
		Type:        "source.rate_limit_drops_sustained",
		ResourceRef: resource,
		Threshold:   1,
		Window:      contracts.NewDuration(window),
		Scope:       "source",
		Subject:     subject,
		Params:      detectionRuntimeParams(params, true),
		ReasonCodes: reasons,
	}, nil
}

func parseSignalDetection(tokens []string, explicitID string) (contracts.RuntimeDetectionRule, error) {
	if len(tokens) < 2 {
		return contracts.RuntimeDetectionRule{}, fmt.Errorf("signal detection requires a signal id")
	}
	signalID := tokens[1]
	params := map[string]any{"signal_type": signalID}
	if len(tokens) > 2 {
		if len(tokens) != 5 || tokens[2] != "score" || !isOperator(tokens[3]) {
			return contracts.RuntimeDetectionRule{}, fmt.Errorf("signal detection supports optional 'score <operator> <number>'")
		}
		operator := normalizeOperator(tokens[3])
		if operator != "gte" && operator != "gt" {
			return contracts.RuntimeDetectionRule{}, fmt.Errorf("signal score detection currently supports gt/gte")
		}
		score, err := strconv.ParseFloat(tokens[4], 64)
		if err != nil {
			return contracts.RuntimeDetectionRule{}, fmt.Errorf("signal score must be numeric")
		}
		params["min_score"] = score
	}
	id := explicitID
	if id == "" {
		id = "signal-" + slug(signalID)
	}
	return contracts.RuntimeDetectionRule{
		ID:          id,
		Type:        "signal.threshold",
		Threshold:   1,
		Scope:       "source",
		Params:      detectionRuntimeParams(params, false),
		ReasonCodes: []string{"signal_observed", "signal_" + strings.ReplaceAll(slug(signalID), "-", "_")},
	}, nil
}

func parseConditionDetection(tokens []string, explicitID string) (contracts.RuntimeDetectionRule, error) {
	tokens = expandNaturalConditionTokens(tokens)
	opIndex := -1
	for i, tok := range tokens {
		if isOperator(tok) {
			opIndex = i
			break
		}
	}
	if opIndex <= 0 || opIndex == len(tokens)-1 {
		return contracts.RuntimeDetectionRule{}, fmt.Errorf("detection condition must use '<signal> <operator> <value>'")
	}
	signal := normalizeSignal(tokens[:opIndex])
	operator := normalizeOperator(tokens[opIndex])
	value := parseConditionValue(operator, tokens[opIndex+1:])
	id := explicitID
	if id == "" {
		id = "signal-" + slug(signal) + "-" + slug(operator) + "-" + slug(valueString(value))
	}
	return contracts.RuntimeDetectionRule{
		ID:        id,
		Type:      responseRuleMetricThreshold,
		Threshold: 1,
		Scope:     "source",
		Params: detectionRuntimeParams(map[string]any{
			"key":      signal,
			"signal":   signal,
			"operator": operator,
			"value":    value,
		}, false),
		ReasonCodes: []string{"signal_condition_matched", "signal_" + strings.ReplaceAll(slug(signal), "-", "_")},
	}, nil
}

func expandNaturalConditionTokens(tokens []string) []string {
	if len(tokens) < 4 {
		return tokens
	}
	for i := 1; i+2 < len(tokens); i++ {
		if tokens[i] != "at" || tokens[i+1] != "least" {
			continue
		}
		signalTokens := tokens[:i]
		if normalizeSignal(signalTokens) != "subject.risk.level" {
			return tokens
		}
		level := strings.Join(tokens[i+2:], " ")
		values := riskLevelsAtLeast(level)
		out := make([]string, 0, len(signalTokens)+1+len(values))
		out = append(out, signalTokens...)
		out = append(out, "in")
		out = append(out, values...)
		return out
	}
	return tokens
}

func riskLevelsAtLeast(level string) []string {
	switch strings.TrimSpace(strings.ToLower(level)) {
	case "low":
		return []string{"low", "medium", "high", "critical"}
	case "medium":
		return []string{"medium", "high", "critical"}
	case "high":
		return []string{"high", "critical"}
	case "critical":
		return []string{"critical"}
	default:
		return []string{strings.TrimSpace(level)}
	}
}

func parseDetectionSubjectSelector(tokens []string) (contracts.RuntimeDetectionSubject, map[string]any, string, error) {
	if len(tokens) == 0 {
		return contracts.RuntimeDetectionSubject{}, nil, "", nil
	}
	if len(tokens) >= 2 && tokens[0] == "group" {
		return contracts.RuntimeDetectionSubject{Type: "group", Ref: strings.Join(tokens[1:], " ")}, nil, "subject_group_matched", nil
	}
	if len(tokens) == 2 && tokens[0] == "unknown" && tokens[1] == "source" {
		return contracts.RuntimeDetectionSubject{Selector: "unknown_source"}, map[string]any{
			"selector": "unknown_source",
		}, "unknown_source_matched", nil
	}
	if len(tokens) >= 5 && tokens[0] == "known" && tokens[1] == "subject" && tokens[2] == "excluding" && tokens[3] == "group" {
		group := strings.Join(tokens[4:], " ")
		return contracts.RuntimeDetectionSubject{Type: "group", Ref: group, Selector: "known_subject_excluding_group"}, map[string]any{
			"selector":       "known_subject_excluding_group",
			"excluded_group": group,
		}, "known_subject_excluding_group", nil
	}
	if len(tokens) == 2 && tokens[0] == "known" && tokens[1] == "subject" {
		return contracts.RuntimeDetectionSubject{Selector: "known_subject"}, map[string]any{
			"selector": "known_subject",
		}, "known_subject_matched", nil
	}
	return contracts.RuntimeDetectionSubject{}, nil, "", fmt.Errorf("unsupported detection subject selector %q", strings.Join(tokens, " "))
}

func parseOnResponse(tokens []string) (contracts.RuntimeResponseRule, error) {
	thenIndex := indexToken(tokens, "then")
	if thenIndex <= 0 {
		return contracts.RuntimeResponseRule{}, fmt.Errorf("response must use 'on <detection> then <action>'")
	}
	if thenIndex == len(tokens)-1 {
		return contracts.RuntimeResponseRule{}, fmt.Errorf("response then requires an action")
	}
	detectionID := strings.Join(tokens[:thenIndex], " ")
	action, err := parseResponseAction(tokens[thenIndex+1:])
	if err != nil {
		return contracts.RuntimeResponseRule{}, err
	}
	actionSlug := slug(action.ID)
	if action.Route != "" {
		actionSlug = slug(action.Route)
	}
	return contracts.RuntimeResponseRule{
		ID: "on-" + slug(detectionID) + "-" + actionSlug,
		When: contracts.RuntimeResponseTrigger{
			Detection: detectionID,
		},
		Then: []contracts.RuntimeResponseAction{action},
		ReasonCodes: []string{
			"response_on_" + strings.ReplaceAll(slug(detectionID), "-", "_"),
		},
	}, nil
}

func applyResponseRequirement(rule *contracts.RuntimeResponseRule, tokens []string) (string, string, error) {
	if len(tokens) >= 4 && tokens[0] == "previous" && tokens[1] == "action" && tokens[len(tokens)-1] == "active" {
		actionID := strings.Join(tokens[2:len(tokens)-1], " ")
		if strings.TrimSpace(actionID) == "" {
			return "", "", fmt.Errorf("previous action requirement needs an action id")
		}
		for i := range rule.Then {
			if rule.Then[i].Params == nil {
				rule.Then[i].Params = map[string]any{}
			}
			rule.Then[i].Params["previous_action_id"] = actionID
			rule.Then[i].Params["previous_action_active"] = true
			if _, ok := rule.Then[i].Params["previous_action_evidence"]; !ok {
				rule.Then[i].Params["previous_action_evidence"] = []string{"runtime_response_state"}
			}
		}
		rule.ReasonCodes = appendUniqueString(rule.ReasonCodes, "requires_previous_action_active")
		return fmt.Sprintf("ENFORCED response rule %q requires previous action %q to be active", rule.ID, actionID), "", nil
	}
	if len(tokens) >= 5 && tokens[0] == "enforcement" && tokens[1] == "target" && tokens[2] == "excludes" && tokens[3] == "group" {
		group := strings.Join(tokens[4:], " ")
		for i := range rule.Then {
			if rule.Then[i].Params == nil {
				rule.Then[i].Params = map[string]any{}
			}
			rule.Then[i].Params["requires_target_excludes_group"] = group
			rule.Then[i].Params["blast_radius_check"] = "exclude_protected_subject"
			rule.Then[i].Params["blast_radius"] = map[string]any{
				"unknown_behavior": "reject_hard_action",
				"excludes": []map[string]string{{
					"type": "group",
					"ref":  group,
				}},
			}
		}
		rule.ReasonCodes = appendUniqueString(rule.ReasonCodes, "requires_blast_radius_exclusion")
		return fmt.Sprintf("ENFORCED response rule %q records blast-radius requirement excluding group %q", rule.ID, group), "", nil
	}
	if len(tokens) == 5 && tokens[0] == "risk" && tokens[1] == "confidence" && tokens[2] == "at" && tokens[3] == "least" {
		minConfidence, ok := riskConfidenceThreshold(tokens[4])
		if !ok {
			return "", "", fmt.Errorf("unsupported risk confidence level %q", tokens[4])
		}
		for i := range rule.Then {
			if rule.Then[i].Params == nil {
				rule.Then[i].Params = map[string]any{}
			}
			rule.Then[i].Params["min_risk_confidence"] = minConfidence
			rule.Then[i].Params["risk_confidence_level"] = tokens[4]
		}
		rule.ReasonCodes = appendUniqueString(rule.ReasonCodes, "requires_risk_confidence")
		return fmt.Sprintf("ENFORCED response rule %q requires risk confidence at least %s", rule.ID, tokens[4]), "", nil
	}
	if len(tokens) == 5 && tokens[0] == "risk" && tokens[1] == "signal" && tokens[2] == "fresher" && tokens[3] == "than" {
		maxAge, err := parseDurationToken(tokens[4])
		if err != nil {
			return "", "", fmt.Errorf("risk signal freshness: %w", err)
		}
		for i := range rule.Then {
			if rule.Then[i].Params == nil {
				rule.Then[i].Params = map[string]any{}
			}
			rule.Then[i].Params["max_risk_age_seconds"] = int(maxAge.Seconds())
			rule.Then[i].Params["risk_freshness_max_age"] = maxAge.String()
		}
		rule.ReasonCodes = appendUniqueString(rule.ReasonCodes, "requires_fresh_risk_signal")
		return fmt.Sprintf("ENFORCED response rule %q requires risk signal fresher than %s", rule.ID, maxAge), "", nil
	}
	if len(tokens) >= 7 && tokens[0] == "at" && tokens[1] == "least" && tokens[3] == "independent" && tokens[4] == "signals" && tokens[5] == "before" {
		n, err := strconv.Atoi(tokens[2])
		if err != nil || n <= 0 {
			return "", "", fmt.Errorf("independent signal requirement must use a positive integer")
		}
		stage := strings.Join(tokens[6:], " ")
		for i := range rule.Then {
			if rule.Then[i].Params == nil {
				rule.Then[i].Params = map[string]any{}
			}
			rule.Then[i].Params["min_independent_signals"] = n
			rule.Then[i].Params["independent_signals_before"] = stage
		}
		rule.ReasonCodes = appendUniqueString(rule.ReasonCodes, "requires_independent_signals")
		return fmt.Sprintf("ENFORCED response rule %q requires at least %d independent signals before %s", rule.ID, n, stage), "", nil
	}
	return "", "", fmt.Errorf("unsupported response requirement %q", strings.Join(tokens, " "))
}

func applyResponseAllowance(rule *contracts.RuntimeResponseRule, tokens []string) (string, error) {
	if len(tokens) == 4 && tokens[0] == "local" && tokens[1] == "enforcement" && tokens[2] == "state" && tokens[3] == "evidence" {
		for i := range rule.Then {
			if rule.Then[i].Params == nil {
				rule.Then[i].Params = map[string]any{}
			}
			evidence := stringListParam(rule.Then[i].Params, "previous_action_evidence")
			evidence = appendUniqueString(evidence, "local_runtime_state")
			rule.Then[i].Params["previous_action_evidence"] = evidence
			rule.Then[i].Params["allow_local_runtime_state_evidence"] = true
		}
		rule.ReasonCodes = appendUniqueString(rule.ReasonCodes, "allows_local_runtime_state_evidence")
		return fmt.Sprintf("ENFORCED response rule %q may use local enforcement state as previous-action evidence", rule.ID), nil
	}
	return "", fmt.Errorf("unsupported response allowance %q", strings.Join(tokens, " "))
}

func responseRuleWarnings(lineNo int, rule contracts.RuntimeResponseRule) []string {
	var warnings []string
	for _, action := range rule.Then {
		if escalation := strings.TrimSpace(fmt.Sprint(action.Params["escalation"])); escalation != "" && escalation != "<nil>" {
			warnings = append(warnings, fmt.Sprintf("line %d: WARNING response escalation %q is carried as action metadata but not enforced as a progressive runtime strategy yet", lineNo, escalation))
		}
	}
	return warnings
}

func applyAutonomyLine(lifecycle **contracts.RuntimeAutonomyLifecycleSpec, tokens []string) (string, string, error) {
	if len(tokens) == 0 {
		return "", "", fmt.Errorf("autonomy statement is empty")
	}
	if *lifecycle == nil {
		*lifecycle = &contracts.RuntimeAutonomyLifecycleSpec{}
	}
	switch {
	case tokens[0] == "hold":
		hold, err := parseAutonomyHold(tokens)
		if err != nil {
			return "", "", err
		}
		(*lifecycle).Hold = append((*lifecycle).Hold, hold)
		return fmt.Sprintf("ENFORCED autonomy hold %q is emitted as RuntimePolicyPack autonomy_lifecycle", hold.ID), "", nil
	case len(tokens) == 7 && tokens[0] == "step_down" && tokens[1] == "after" && tokens[2] == "clean" && tokens[4] == "observe" && tokens[5] == "after":
		cleanAfter, err := parseDurationToken(tokens[3])
		if err != nil {
			return "", "", fmt.Errorf("autonomy step_down clean_after: %w", err)
		}
		observeAfter, err := parseDurationToken(tokens[6])
		if err != nil {
			return "", "", fmt.Errorf("autonomy step_down observe_after: %w", err)
		}
		(*lifecycle).StepDown = contracts.RuntimeAutonomyStepDown{
			CleanAfter:   contracts.NewDuration(cleanAfter),
			ObserveAfter: contracts.NewDuration(observeAfter),
		}
		return "CARRIED autonomy step_down is emitted as RuntimePolicyPack autonomy_lifecycle",
			"WARNING autonomy step_down is carried but not enforced by KLIQ runtime lifecycle yet", nil
	case len(tokens) == 3 && tokens[0] == "max" && tokens[1] == "renewals":
		renewals, err := strconv.Atoi(tokens[2])
		if err != nil || renewals < 0 {
			return "", "", fmt.Errorf("autonomy max renewals must be a non-negative integer")
		}
		(*lifecycle).MaxRenewals = renewals
		return "ENFORCED autonomy max renewals is emitted as RuntimePolicyPack autonomy_lifecycle", "", nil
	case len(tokens) == 8 && tokens[0] == "restore" && tokens[1] == "previous" && tokens[2] == "mitigation" && tokens[3] == "if" && tokens[4] == "pressure" && tokens[5] == "resumes" && tokens[6] == "during" && tokens[7] == "cooldown":
		(*lifecycle).RestorePreviousOnResume = true
		return "CARRIED autonomy restore-on-resume is emitted as RuntimePolicyPack autonomy_lifecycle",
			"WARNING autonomy restore previous mitigation is carried but not enforced by KLIQ cooldown lifecycle yet", nil
	case len(tokens) >= 5 && tokens[0] == "allow" && tokens[1] == "autonomous":
		allowance, err := parseAutonomyAllowance(tokens[2:])
		if err != nil {
			return "", "", err
		}
		(*lifecycle).Allow = append((*lifecycle).Allow, allowance)
		if allowance.RequiresPreviousAction != "" {
			return fmt.Sprintf("ENFORCED autonomy allowance for %q is emitted as RuntimePolicyPack autonomy_lifecycle", allowance.Action), "", nil
		}
		return fmt.Sprintf("ENFORCED autonomy allowance for %q is emitted as RuntimePolicyPack autonomy_lifecycle", allowance.Action), "", nil
	case len(tokens) == 5 && tokens[0] == "require" && tokens[1] == "approval" && tokens[2] == "before":
		action, err := autonomyActionCapability(tokens[3:])
		if err != nil {
			return "", "", err
		}
		(*lifecycle).ApprovalRequired = append((*lifecycle).ApprovalRequired, contracts.RuntimeAutonomyApprovalRequirement{
			Action:      action,
			ReasonCodes: []string{"requires_operator_approval"},
		})
		return fmt.Sprintf("ENFORCED autonomy approval requirement for %q is emitted as RuntimePolicyPack autonomy_lifecycle", action), "", nil
	case len(tokens) >= 8 && tokens[0] == "never" && tokens[2] == "more" && tokens[3] == "than" && tokens[5] == "sources":
		limit, err := parseAutonomyBlastRadiusLimit(tokens)
		if err != nil {
			return "", "", err
		}
		(*lifecycle).BlastRadius = append((*lifecycle).BlastRadius, limit)
		return fmt.Sprintf("CARRIED autonomy blast-radius limit for %q is emitted as RuntimePolicyPack autonomy_lifecycle", limit.Action),
			"WARNING autonomy blast-radius source-count windows are carried but not enforced by broker counters yet", nil
	case len(tokens) == 5 && tokens[0] == "max" && tokens[1] == "autonomous" && tokens[3] == "duration":
		action, err := autonomyActionCapability([]string{tokens[2]})
		if err != nil {
			return "", "", err
		}
		duration, err := parseDurationToken(tokens[4])
		if err != nil {
			return "", "", fmt.Errorf("autonomy max action duration: %w", err)
		}
		(*lifecycle).MaxActionDuration = append((*lifecycle).MaxActionDuration, contracts.RuntimeAutonomyActionDurationLimit{
			Action:   action,
			Duration: contracts.NewDuration(duration),
		})
		return fmt.Sprintf("ENFORCED autonomy max duration for %q is emitted as RuntimePolicyPack autonomy_lifecycle", action), "", nil
	case len(tokens) == 6 && tokens[0] == "require" && tokens[1] == "audit" && tokens[2] == "receipt" && tokens[3] == "for" && tokens[4] == "every" && tokens[5] == "enforcement":
		(*lifecycle).RequiresAudit = true
		return "ENFORCED autonomy audit receipt requirement is emitted as RuntimePolicyPack autonomy_lifecycle", "", nil
	default:
		return "", "", fmt.Errorf("unsupported autonomy statement %q", strings.Join(tokens, " "))
	}
}

func parseAutonomyAllowance(tokens []string) (contracts.RuntimeAutonomyAllowance, error) {
	forIndex := indexToken(tokens, "for")
	if forIndex > 0 {
		action, err := autonomyActionCapability(tokens[:forIndex])
		if err != nil {
			return contracts.RuntimeAutonomyAllowance{}, err
		}
		if len(tokens[forIndex+1:]) == 2 && tokens[forIndex+1] == "unknown" && tokens[forIndex+2] == "sources" {
			return contracts.RuntimeAutonomyAllowance{
				Action:      action,
				Subject:     contracts.RuntimeAutonomySubject{Type: "source", Ref: "unknown"},
				ReasonCodes: []string{"allow_autonomous_unknown_source"},
			}, nil
		}
		return contracts.RuntimeAutonomyAllowance{}, fmt.Errorf("autonomy allowance subject must be 'unknown sources'")
	}
	onlyIndex := indexToken(tokens, "only")
	if onlyIndex > 0 && len(tokens[onlyIndex:]) == 5 && tokens[onlyIndex+1] == "after" && tokens[onlyIndex+3] == "was" && tokens[onlyIndex+4] == "active" {
		action, err := autonomyActionCapability(tokens[:onlyIndex])
		if err != nil {
			return contracts.RuntimeAutonomyAllowance{}, err
		}
		previous, err := autonomyActionCapability([]string{tokens[onlyIndex+2]})
		if err != nil {
			return contracts.RuntimeAutonomyAllowance{}, err
		}
		return contracts.RuntimeAutonomyAllowance{
			Action:                 action,
			RequiresPreviousAction: previous,
			ReasonCodes:            []string{"allow_autonomous_after_previous_action"},
		}, nil
	}
	return contracts.RuntimeAutonomyAllowance{}, fmt.Errorf("unsupported autonomy allowance %q", strings.Join(tokens, " "))
}

func parseAutonomyBlastRadiusLimit(tokens []string) (contracts.RuntimeAutonomyBlastRadiusLimit, error) {
	action, err := autonomyActionCapability([]string{tokens[1]})
	if err != nil {
		return contracts.RuntimeAutonomyBlastRadiusLimit{}, err
	}
	maxTargets, err := strconv.Atoi(tokens[4])
	if err != nil || maxTargets <= 0 {
		return contracts.RuntimeAutonomyBlastRadiusLimit{}, fmt.Errorf("autonomy blast-radius max targets must be a positive integer")
	}
	withinIndex := indexToken(tokens, "within")
	if withinIndex < 0 || withinIndex == len(tokens)-1 {
		return contracts.RuntimeAutonomyBlastRadiusLimit{}, fmt.Errorf("autonomy blast-radius limit requires within <duration>")
	}
	window, err := parseDurationToken(tokens[withinIndex+1])
	if err != nil {
		return contracts.RuntimeAutonomyBlastRadiusLimit{}, fmt.Errorf("autonomy blast-radius window: %w", err)
	}
	scope := "tenant"
	if perIndex := indexToken(tokens, "per"); perIndex >= 0 && perIndex < len(tokens)-1 {
		scope = tokens[perIndex+1]
	}
	return contracts.RuntimeAutonomyBlastRadiusLimit{
		Action:     action,
		MaxTargets: maxTargets,
		Scope:      scope,
		Window:     contracts.NewDuration(window),
	}, nil
}

func riskConfidenceThreshold(level string) (float64, bool) {
	switch strings.TrimSpace(level) {
	case "low":
		return 0.4, true
	case "medium":
		return 0.6, true
	case "high":
		return 0.8, true
	case "critical":
		return 0.95, true
	default:
		return 0, false
	}
}

func autonomyActionCapability(tokens []string) (string, error) {
	action := strings.Join(tokens, " ")
	action = strings.ReplaceAll(action, " ", "_")
	switch action {
	case "rate_limit":
		return "enforce.traffic.rate_limit", nil
	case "temporary_block", "block":
		return "enforce.traffic.drop", nil
	case "identity_disable", "disable_identity":
		return "enforce.identity.disable", nil
	default:
		_, capability := normalizeResponseAction(tokens)
		if capability != "" {
			return capability, nil
		}
		return "", fmt.Errorf("unsupported autonomy action %q", strings.Join(tokens, " "))
	}
}

func parseAutonomyHold(tokens []string) (contracts.RuntimeAutonomyHoldRule, error) {
	forIndex := indexToken(tokens, "for")
	if forIndex <= 1 || forIndex == len(tokens)-1 {
		return contracts.RuntimeAutonomyHoldRule{}, fmt.Errorf("autonomy hold must use 'hold <action> [source] [at <pps> pps] for <duration> while enforcement feedback active'")
	}
	ttl, err := parseDurationToken(tokens[forIndex+1])
	if err != nil {
		return contracts.RuntimeAutonomyHoldRule{}, fmt.Errorf("autonomy hold ttl: %w", err)
	}
	if forIndex+2 >= len(tokens) || tokens[forIndex+2] != "while" {
		return contracts.RuntimeAutonomyHoldRule{}, fmt.Errorf("autonomy hold requires 'while enforcement feedback active'")
	}
	condition, err := parseAutonomyHoldCondition(tokens[forIndex+3:])
	if err != nil {
		return contracts.RuntimeAutonomyHoldRule{}, err
	}
	actionTokens := append([]string(nil), tokens[1:forIndex]...)
	params := map[string]any{}
	if atIndex := indexToken(actionTokens, "at"); atIndex >= 0 {
		if atIndex+2 >= len(actionTokens) || actionTokens[atIndex+2] != "pps" {
			return contracts.RuntimeAutonomyHoldRule{}, fmt.Errorf("autonomy hold rate must use 'at <number> pps'")
		}
		rate, err := strconv.Atoi(actionTokens[atIndex+1])
		if err != nil || rate <= 0 {
			return contracts.RuntimeAutonomyHoldRule{}, fmt.Errorf("autonomy hold rate must be a positive integer")
		}
		params["rate_pps"] = rate
		actionTokens = append(actionTokens[:atIndex], actionTokens[atIndex+3:]...)
	}
	if len(actionTokens) > 0 && actionTokens[len(actionTokens)-1] == "source" {
		actionTokens = actionTokens[:len(actionTokens)-1]
	}
	naturalAction, capability := normalizeResponseAction(actionTokens)
	if capability == "" {
		return contracts.RuntimeAutonomyHoldRule{}, fmt.Errorf("unsupported autonomy hold action %q", strings.Join(actionTokens, " "))
	}
	if len(params) == 0 {
		params = nil
	} else {
		params["natural_action"] = naturalAction
	}
	level := "hard"
	if capability == "enforce.traffic.drop" || capability == "enforce.access.deny" {
		level = "block"
	}
	return contracts.RuntimeAutonomyHoldRule{
		ID:    "hold-" + slug(naturalAction) + "-while-enforcement-feedback-active",
		While: condition,
		Action: contracts.RuntimeActionSpec{
			Capability: capability,
			Level:      level,
			TTL:        contracts.NewDuration(ttl),
			Params:     params,
		},
		ReasonCodes: []string{"rate_limit_drops_sustained", "enforcement_hold"},
	}, nil
}

func parseAutonomyHoldCondition(tokens []string) (contracts.RuntimeAutonomyHoldCondition, error) {
	if len(tokens) == 3 && tokens[0] == "enforcement" && tokens[1] == "feedback" && tokens[2] == "active" {
		return contracts.RuntimeAutonomyHoldCondition{
			EnforcementFeedbackActive: true,
			Levels:                    []string{"soft", "hard", "block"},
		}, nil
	}
	return contracts.RuntimeAutonomyHoldCondition{}, fmt.Errorf("autonomy hold condition must be 'enforcement feedback active'")
}

func ensureAlertRouteDefinition(routes map[string]*alertRouteDefinition, routeID string) *alertRouteDefinition {
	if routes[routeID] == nil {
		routes[routeID] = &alertRouteDefinition{ID: routeID}
	}
	return routes[routeID]
}

func applyAlertRouteLine(routes map[string]*alertRouteDefinition, routeID string, tokens []string) error {
	route := ensureAlertRouteDefinition(routes, routeID)
	switch tokens[0] {
	case "notify":
		if len(tokens) < 3 {
			return fmt.Errorf("notify must use 'notify <audience-type> <ref>'")
		}
		route.Audience = contracts.RuntimeAlertAudience{
			Type: tokens[1],
			Ref:  strings.Join(tokens[2:], " "),
		}
	case "via":
		channels := parseStringListTokens(tokens[1:])
		route.Channels = route.Channels[:0]
		for _, ch := range channels {
			route.Channels = append(route.Channels, contracts.RuntimeAlertChannel{Type: ch, Ref: alertChannelRef(ch, routeID)})
		}
	case "dedupe":
		if len(tokens) < 3 || tokens[1] != "by" {
			return fmt.Errorf("dedupe must use 'dedupe by [...]'")
		}
		route.DedupeKeys = parseStringListTokens(tokens[2:])
	case "create":
		if len(tokens) < 3 || tokens[1] != "case" {
			return fmt.Errorf("create must use 'create case <true|false>'")
		}
		create := tokens[2] == "true" || tokens[2] == "yes"
		route.CreateCase = &create
	case "require":
		if len(tokens) != 4 || tokens[1] != "acknowledgement" || tokens[2] != "within" {
			return fmt.Errorf("require must use 'require acknowledgement within <duration>'")
		}
		timeout, err := parseDurationToken(tokens[3])
		if err != nil {
			return fmt.Errorf("acknowledgement timeout: %w", err)
		}
		route.AckRequired = true
		route.AckTimeout = timeout
	case "escalate":
		if len(tokens) < 6 || tokens[1] != "if" || tokens[2] != "unacknowledged" || tokens[3] != "to" {
			return fmt.Errorf("escalate must use 'escalate if unacknowledged to <audience-type> <ref>'")
		}
		route.Escalations = append(route.Escalations, contracts.RuntimeAlertEscalation{
			To: contracts.RuntimeAlertAudience{
				Type: tokens[4],
				Ref:  strings.Join(tokens[5:], " "),
			},
			Via: []string{"email", "log"},
		})
	default:
		return fmt.Errorf("unsupported alert_route statement %q", strings.Join(tokens, " "))
	}
	return nil
}

func alertChannelRef(channelType, routeID string) string {
	short := strings.TrimPrefix(routeID, "alert-route.")
	switch strings.ReplaceAll(strings.ToLower(strings.TrimSpace(channelType)), "-", "_") {
	case "log":
		return "log." + short
	case "email":
		return "channel." + short
	default:
		return "channel." + short
	}
}

func applyAlertRouteDefinitions(responses []contracts.RuntimeResponseRule, routes map[string]*alertRouteDefinition) {
	for i := range responses {
		for j := range responses[i].Then {
			action := &responses[i].Then[j]
			if action.ID != "notify.alert.emit" || action.Route == "" {
				continue
			}
			route := routes[action.Route]
			if route == nil {
				continue
			}
			if action.Params == nil {
				action.Params = map[string]any{}
			}
			if route.Audience.Type != "" || route.Audience.Ref != "" {
				action.Params["route_audience_type"] = route.Audience.Type
				action.Params["route_audience_ref"] = route.Audience.Ref
			}
			if len(route.Channels) > 0 {
				channels := make([]string, 0, len(route.Channels))
				for _, ch := range route.Channels {
					channels = append(channels, ch.Type)
				}
				action.Params["route_channels"] = channels
			}
			if len(route.DedupeKeys) > 0 {
				action.Params["route_dedupe_keys"] = append([]string(nil), route.DedupeKeys...)
			}
			if route.CreateCase != nil {
				action.Params["create_case"] = *route.CreateCase
			}
			if route.AckRequired {
				action.Params["ack_required"] = true
				action.Params["ack_timeout"] = route.AckTimeout.String()
			}
			if len(route.Escalations) > 0 {
				action.Params["escalation_count"] = len(route.Escalations)
			}
		}
	}
}

func runtimeAlertRoutesFromDefinitions(routes map[string]*alertRouteDefinition) []contracts.RuntimeAlertRoute {
	out := make([]contracts.RuntimeAlertRoute, 0, len(routes))
	for _, route := range routes {
		if route == nil || route.ID == "" {
			continue
		}
		dedupeKeys := route.DedupeKeys
		if len(dedupeKeys) == 0 {
			dedupeKeys = []string{"resource.id", "detection.id", "source.identity_or_ip"}
		}
		createCase := false
		if route.CreateCase != nil {
			createCase = *route.CreateCase
		}
		out = append(out, contracts.RuntimeAlertRoute{
			ID:              route.ID,
			Audience:        route.Audience,
			Channels:        append([]contracts.RuntimeAlertChannel(nil), route.Channels...),
			DefaultSeverity: route.DefaultSeverity,
			Deduplication: contracts.RuntimeAlertDeduplication{
				Enabled: true,
				Window:  contracts.NewDuration(15 * time.Minute),
				Keys:    append([]string(nil), dedupeKeys...),
			},
			CaseManagement: contracts.RuntimeAlertCaseManagement{
				CreateCase: createCase,
			},
			Acknowledgement: contracts.RuntimeAlertAcknowledgement{
				Required:     route.AckRequired,
				Timeout:      contracts.NewDuration(route.AckTimeout),
				NoEscalation: route.AckRequired && len(route.Escalations) == 0,
				Escalation:   append([]contracts.RuntimeAlertEscalation(nil), route.Escalations...),
			},
		})
	}
	return out
}

func applyCapabilityRequirementLine(req *CapabilityRequirement, tokens []string) error {
	if len(tokens) == 0 {
		return nil
	}
	if tokens[0] != "require" {
		return fmt.Errorf("capabilities block supports only require statements")
	}
	if len(tokens) < 2 {
		return fmt.Errorf("capability require needs a value")
	}
	if tokens[1] == "context" {
		if len(tokens) < 3 {
			return fmt.Errorf("require context needs a key")
		}
		req.Spec.Required = append(req.Spec.Required, CapabilityRequirementItem{Context: strings.Join(tokens[2:], " ")})
		return nil
	}
	value := strings.Join(tokens[1:], "_")
	switch value {
	case "identity_based_access":
		req.Spec.Required = append(req.Spec.Required, CapabilityRequirementItem{Feature: value})
	case "windowed_detection":
		req.Spec.Required = append(req.Spec.Required, CapabilityRequirementItem{Feature: value})
	case "traffic_rate_limit":
		req.Spec.Required = append(req.Spec.Required, CapabilityRequirementItem{Capability: "enforce.traffic.rate_limit"})
	case "temporary_traffic_block", "temporary_block":
		req.Spec.Required = append(req.Spec.Required, CapabilityRequirementItem{Capability: "enforce.traffic.drop"})
	default:
		req.Spec.Required = append(req.Spec.Required, CapabilityRequirementItem{Feature: value})
	}
	return nil
}

func applyGapHandlingLine(req *CapabilityRequirement, tokens []string) error {
	if len(tokens) < 3 {
		return fmt.Errorf("gap_handling must use '<behavior> on <gap>'")
	}
	if tokens[1] != "on" {
		return fmt.Errorf("gap_handling must use '<behavior> on <gap>'")
	}
	req.Spec.GapHandling = append(req.Spec.GapHandling, GapHandlingRule{
		Behavior: tokens[0],
		Gap:      strings.Join(tokens[2:], "_"),
	})
	return nil
}

func parseStringListTokens(tokens []string) []string {
	var out []string
	for _, tok := range tokens {
		for _, part := range strings.Split(tok, ",") {
			part = strings.Trim(part, "[] \"'")
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func stringListParam(params map[string]any, key string) []string {
	value, ok := params[key]
	if !ok {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case string:
		return parseStringListTokens([]string{typed})
	default:
		return []string{fmt.Sprint(typed)}
	}
}

func appendUniqueString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func parseRequire(tokens []string) (intent.Condition, error) {
	opIndex := -1
	for i, tok := range tokens {
		if isOperator(tok) {
			opIndex = i
			break
		}
	}
	if opIndex <= 0 {
		return intent.Condition{}, fmt.Errorf("require must use '<signal> <operator> <value>'")
	}
	if opIndex == len(tokens)-1 {
		return intent.Condition{}, fmt.Errorf("require is missing a value")
	}
	signal := normalizeSignal(tokens[:opIndex])
	if signal == "" {
		return intent.Condition{}, fmt.Errorf("require is missing a signal")
	}
	operator := normalizeOperator(tokens[opIndex])
	value := parseConditionValue(operator, tokens[opIndex+1:])
	return intent.Condition{
		Type:     conditionTypeForSignal(signal),
		Signal:   signal,
		Operator: operator,
		Value:    value,
	}, nil
}

func normalizeSignal(tokens []string) string {
	raw := strings.Join(tokens, " ")
	switch raw {
	case "risk", "subject risk", "subject risk level":
		return "subject.risk.level"
	case "subject id", "identity":
		return "subject.id"
	case "subject type":
		return "subject.type"
	case "role", "subject role":
		return "subject.role"
	case "group", "groups", "subject group", "subject groups":
		return "subject.group"
	case "identity assurance", "subject identity assurance":
		return "subject.identity_assurance"
	case "employment status", "subject employment status":
		return "subject.employment_status"
	case "subject anomaly", "behavior anomaly", "subject behavior anomaly":
		return "subject.behavior.anomaly_detected"
	case "device id":
		return "device.id"
	case "device managed", "device management", "device management status":
		return "device.management.status"
	case "device risk", "device risk level":
		return "device.risk.level"
	case "session risk", "session risk level":
		return "session.risk.level"
	case "posture", "device posture", "device posture status":
		return "device.posture.status"
	case "edr", "device edr", "device edr status":
		return "device.edr.status"
	case "device attestation", "device attestation status":
		return "device.attestation.status"
	case "resource id":
		return "resource.id"
	case "resource type":
		return "resource.type"
	case "resource application group", "application group":
		return "resource.application_group"
	case "resource data class", "data class":
		return "resource.data_class"
	case "resource criticality", "criticality":
		return "resource.criticality"
	case "resource environment", "environment":
		return "resource.environment"
	case "resource owner":
		return "resource.owner"
	case "resource exposure", "exposure":
		return "resource.exposure"
	case "session id":
		return "session.id"
	case "session authentication", "session authentication strength":
		return "session.authentication.strength"
	case "location", "session location":
		return "session.location"
	case "session network zone":
		return "session.network_zone"
	case "workload id":
		return "workload.id"
	case "workload namespace", "namespace":
		return "workload.namespace"
	case "workload service account":
		return "workload.service_account"
	case "workload image", "workload image identity":
		return "workload.image.identity"
	case "workload attestation", "workload attestation status":
		return "workload.attestation.status"
	case "workload environment":
		return "workload.environment"
	case "network source":
		return "network.source"
	case "network destination":
		return "network.destination"
	case "network protocol":
		return "network.protocol"
	case "network port":
		return "network.port"
	case "network zone":
		return "network.zone"
	default:
		return raw
	}
}

func conditionTypeForSignal(signal string) string {
	switch {
	case strings.HasSuffix(signal, ".risk.level"):
		return "risk_level"
	case strings.HasPrefix(signal, "device.posture"),
		strings.HasPrefix(signal, "device.edr"),
		strings.HasPrefix(signal, "device.attestation"),
		strings.HasPrefix(signal, "workload.attestation"):
		return "device_posture"
	case strings.HasPrefix(signal, "session.authentication"),
		strings.HasPrefix(signal, "subject.identity_assurance"):
		return "authentication_strength"
	case strings.HasPrefix(signal, "network."):
		return "network_tuple"
	case strings.HasPrefix(signal, "session."):
		return "session_context"
	case strings.HasPrefix(signal, "subject."):
		return "subject_context"
	case strings.HasPrefix(signal, "resource."):
		return "resource_context"
	case strings.HasPrefix(signal, "workload."):
		return "device_posture"
	default:
		return "custom"
	}
}

func parseConditionValue(operator string, tokens []string) any {
	if operator == "in" || operator == "not_in" {
		values := make([]string, 0, len(tokens))
		for _, tok := range tokens {
			for _, part := range strings.Split(tok, ",") {
				part = strings.Trim(part, "[] ")
				if part != "" {
					values = append(values, part)
				}
			}
		}
		return values
	}
	return strings.Join(tokens, " ")
}

func splitOptionalActionTTL(tokens []string) ([]string, string, error) {
	for i, tok := range tokens {
		if tok != "for" {
			continue
		}
		if i == 0 {
			return nil, "", fmt.Errorf("then action is missing before for")
		}
		if i != len(tokens)-2 {
			return nil, "", fmt.Errorf("then action TTL must use 'for <duration>'")
		}
		ttl := tokens[i+1]
		if err := validateDurationToken(ttl); err != nil {
			return nil, "", fmt.Errorf("then action TTL: %w", err)
		}
		return tokens[:i], ttl, nil
	}
	return tokens, "", nil
}

func parseResponseAction(tokens []string) (contracts.RuntimeResponseAction, error) {
	if len(tokens) == 0 {
		return contracts.RuntimeResponseAction{}, fmt.Errorf("then action is missing")
	}
	if tokens[0] == "alert" {
		return parseAlertAction(tokens)
	}
	actionAndTTLTokens, escalation, err := splitOptionalEscalation(tokens)
	if err != nil {
		return contracts.RuntimeResponseAction{}, err
	}
	actionTokens, ttl, err := splitOptionalActionTTL(actionAndTTLTokens)
	if err != nil {
		return contracts.RuntimeResponseAction{}, err
	}
	actionTokens, ratePPS, err := splitOptionalActionRatePPS(actionTokens)
	if err != nil {
		return contracts.RuntimeResponseAction{}, err
	}
	target := contracts.RuntimeResponseTarget{}
	if len(actionTokens) > 1 && isResponseTargetScope(actionTokens[len(actionTokens)-1]) {
		target.Scope = actionTokens[len(actionTokens)-1]
		actionTokens = actionTokens[:len(actionTokens)-1]
	}
	action, canonicalAction := normalizeResponseAction(actionTokens)
	if canonicalAction == "" {
		return contracts.RuntimeResponseAction{}, fmt.Errorf("unsupported response action %q", strings.Join(tokens, " "))
	}
	runtimeAction := contracts.RuntimeResponseAction{
		ID:     canonicalAction,
		Target: target,
		Params: map[string]any{
			"natural_action": action,
		},
	}
	if escalation != "" {
		runtimeAction.Params["escalation"] = escalation
	}
	if ratePPS > 0 {
		runtimeAction.Params["rate_pps"] = ratePPS
	}
	if ttl != "" {
		parsed, err := parseDurationToken(ttl)
		if err != nil {
			return contracts.RuntimeResponseAction{}, fmt.Errorf("then action TTL: %w", err)
		}
		runtimeAction.TTL = contracts.NewDuration(parsed)
	}
	return runtimeAction, nil
}

func splitOptionalActionRatePPS(tokens []string) ([]string, int, error) {
	atIndex := indexToken(tokens, "at")
	if atIndex < 0 {
		return tokens, 0, nil
	}
	if atIndex == 0 {
		return nil, 0, fmt.Errorf("then action is missing before rate")
	}
	if atIndex+2 >= len(tokens) || tokens[atIndex+2] != "pps" {
		return nil, 0, fmt.Errorf("then action rate must use 'at <number> pps'")
	}
	rate, err := strconv.Atoi(tokens[atIndex+1])
	if err != nil || rate <= 0 {
		return nil, 0, fmt.Errorf("then action rate must be a positive integer")
	}
	out := make([]string, 0, len(tokens)-3)
	out = append(out, tokens[:atIndex]...)
	out = append(out, tokens[atIndex+3:]...)
	return out, rate, nil
}

func splitOptionalEscalation(tokens []string) ([]string, string, error) {
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i] != "with" || tokens[i+1] != "escalation" {
			continue
		}
		if i == 0 {
			return nil, "", fmt.Errorf("then action is missing before escalation")
		}
		escalationTokens := tokens[i+2:]
		if len(escalationTokens) == 0 {
			return nil, "", fmt.Errorf("then action escalation requires a value")
		}
		return tokens[:i], strings.Join(escalationTokens, " "), nil
	}
	return tokens, "", nil
}

func parseAlertAction(tokens []string) (contracts.RuntimeResponseAction, error) {
	if len(tokens) < 7 || tokens[1] != "route" {
		return contracts.RuntimeResponseAction{}, fmt.Errorf("alert action must use 'alert route <route> severity <level> dedupe <duration>'")
	}
	route := normalizeAlertRoute(tokens[2])
	severityIndex := indexToken(tokens, "severity")
	dedupeIndex := indexToken(tokens, "dedupe")
	if severityIndex < 0 || severityIndex == len(tokens)-1 {
		return contracts.RuntimeResponseAction{}, fmt.Errorf("alert action requires severity <level>")
	}
	if dedupeIndex < 0 || dedupeIndex == len(tokens)-1 {
		return contracts.RuntimeResponseAction{}, fmt.Errorf("alert action requires dedupe <duration>")
	}
	severity := tokens[severityIndex+1]
	if !isSeverity(severity) {
		return contracts.RuntimeResponseAction{}, fmt.Errorf("unsupported alert severity %q", severity)
	}
	dedupe, err := parseDurationToken(tokens[dedupeIndex+1])
	if err != nil {
		return contracts.RuntimeResponseAction{}, fmt.Errorf("alert dedupe: %w", err)
	}
	params := map[string]any{}
	if hasTokenSequence(tokens, "create", "case") {
		params["create_case"] = true
	}
	return contracts.RuntimeResponseAction{
		ID:       "notify.alert.emit",
		Route:    route,
		Severity: severity,
		Dedupe:   contracts.NewDuration(dedupe),
		Params:   params,
	}, nil
}

func normalizeAlertRoute(route string) string {
	route = strings.TrimSpace(route)
	if route == "" || strings.HasPrefix(route, "alert-route.") {
		return route
	}
	return "alert-route." + route
}

func isSeverity(value string) bool {
	switch value {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func isResponseTargetScope(value string) bool {
	switch value {
	case "source", "subject", "resource":
		return true
	default:
		return false
	}
}

func hasTokenSequence(tokens []string, first, second string) bool {
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i] == first && tokens[i+1] == second {
			return true
		}
	}
	return false
}

func validateDurationToken(value string) error {
	_, err := parseDurationToken(value)
	return err
}

func parseDurationToken(value string) (time.Duration, error) {
	if value == "" {
		return 0, fmt.Errorf("duration is empty")
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%q is not a valid duration", value)
	}
	return parsed, nil
}

func normalizeResponseAction(tokens []string) (string, string) {
	action := strings.Join(tokens, " ")
	action = strings.ReplaceAll(action, " ", "_")
	switch action {
	case "alert":
		return action, "observe.signal.emit"
	case "finding", "export_finding":
		return action, "export.finding"
	case "rate_limit":
		return action, "enforce.traffic.rate_limit"
	case "connection_limit":
		return action, "enforce.traffic.connection_limit"
	case "bandwidth_limit":
		return action, "enforce.traffic.bandwidth_limit"
	case "syn_protect":
		return action, "enforce.network.syn_protect"
	case "deny", "block":
		return action, "enforce.access.deny"
	case "temporary_block":
		return action, "enforce.traffic.drop"
	case "network_deny":
		return action, "enforce.network.deny"
	case "drop":
		return action, "enforce.traffic.drop"
	case "tarpit":
		return action, "enforce.traffic.tarpit"
	case "quarantine":
		return action, "enforce.network.quarantine"
	case "observe.signal.emit",
		"export.finding",
		"enforce.access.deny",
		"enforce.network.rate_limit",
		"enforce.network.syn_protect",
		"enforce.network.deny",
		"enforce.network.quarantine",
		"enforce.traffic.rate_limit",
		"enforce.traffic.connection_limit",
		"enforce.traffic.bandwidth_limit",
		"enforce.traffic.tarpit",
		"enforce.traffic.drop",
		"enforce.traffic.quarantine":
		return action, action
	default:
		return action, ""
	}
}

func uniqueConditionID(seen map[string]int, base string) string {
	if base == "require-" {
		base = "require-condition"
	}
	seen[base]++
	if seen[base] == 1 {
		return base
	}
	return fmt.Sprintf("%s-%d", base, seen[base])
}

func isOperator(s string) bool {
	switch s {
	case "eq", "equals", "is", "neq", "not", "gte", "lte", "gt", "lt", "in", "not_in":
		return true
	default:
		return false
	}
}

func normalizeOperator(s string) string {
	switch s {
	case "equals", "is":
		return "eq"
	case "not":
		return "neq"
	default:
		return s
	}
}

func indexToken(tokens []string, want string) int {
	for i, tok := range tokens {
		if tok == want {
			return i
		}
	}
	return -1
}

func indexTokenBefore(tokens []string, want string, before int) int {
	if before > len(tokens) {
		before = len(tokens)
	}
	for i := 0; i < before; i++ {
		if tokens[i] == want {
			return i
		}
	}
	return -1
}

func indexTokenRange(tokens []string, want string, start, end int) int {
	if start < 0 {
		start = 0
	}
	if end > len(tokens) {
		end = len(tokens)
	}
	for i := start; i < end; i++ {
		if tokens[i] == want {
			return i
		}
	}
	return -1
}

func splitOptionalIn(tokens []string) ([]string, []string) {
	for i, tok := range tokens {
		if tok == "in" {
			return tokens[:i], tokens[i+1:]
		}
	}
	return tokens, nil
}

func splitOptionalAs(tokens []string) ([]string, []string) {
	for i, tok := range tokens {
		if tok == "as" {
			return tokens[:i], tokens[i+1:]
		}
	}
	return tokens, nil
}

func splitAccessStatement(tokens []string) ([]string, []string, error) {
	for i := 0; i+2 < len(tokens); i++ {
		if tokens[i] == "to" && tokens[i+1] == "access" {
			return tokens[:i], tokens[i+2:], nil
		}
	}
	return nil, nil, fmt.Errorf("access statement must use '<subject> to access <resource>'")
}

func isAllowAll(tokens []string) bool {
	return len(tokens) == 1 && (tokens[0] == "all" || tokens[0] == "everyone")
}

func parseSubject(tokens []string, fallbackType string) (string, string) {
	if len(tokens) == 0 {
		return "any", ""
	}
	if len(tokens) == 1 && (tokens[0] == "all" || tokens[0] == "everyone") {
		return "any", ""
	}
	if isSubjectType(tokens[0]) && len(tokens) > 1 {
		return tokens[0], strings.Join(tokens[1:], " ")
	}
	return fallbackType, strings.Join(tokens, " ")
}

func parseResource(tokens []string, fallbackType string) (string, string) {
	if len(tokens) == 0 {
		return fallbackType, ""
	}
	if len(tokens) == 1 && (tokens[0] == "all" || tokens[0] == "everything") {
		return "any", ""
	}
	if isResourceType(tokens[0]) && len(tokens) > 1 {
		return tokens[0], strings.Join(tokens[1:], " ")
	}
	return fallbackType, strings.Join(tokens, " ")
}

func isSubjectType(s string) bool {
	switch s {
	case "any", "role", "group", "user", "service_account", "workload", "device_identity", "automation_identity", "external_partner":
		return true
	default:
		return false
	}
}

func isResourceType(s string) bool {
	switch s {
	case "any", "application", "application_group", "api", "service", "endpoint", "database", "storage", "secret", "network_segment", "infrastructure_asset":
		return true
	default:
		return false
	}
}

func stripComment(line string) string {
	inQuote := false
	var quote rune
	for i, r := range line {
		if inQuote {
			if r == quote {
				inQuote = false
			}
			continue
		}
		if r == '"' || r == '\'' {
			inQuote = true
			quote = r
			continue
		}
		if r == '#' {
			return strings.TrimSpace(line[:i])
		}
	}
	return line
}

func tokenize(line string) ([]string, error) {
	var out []string
	var b strings.Builder
	inQuote := false
	var quote rune

	flush := func() {
		if b.Len() == 0 {
			return
		}
		out = append(out, b.String())
		b.Reset()
	}

	for _, r := range line {
		if inQuote {
			if r == quote {
				inQuote = false
				flush()
				continue
			}
			b.WriteRune(r)
			continue
		}
		if r == '"' || r == '\'' {
			flush()
			inQuote = true
			quote = r
			continue
		}
		if unicode.IsSpace(r) {
			flush()
			continue
		}
		b.WriteRune(r)
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quoted value")
	}
	flush()
	return out, nil
}

func slug(s string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteRune('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
