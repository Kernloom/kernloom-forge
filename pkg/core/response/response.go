// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package response defines authored detection policies, response policies and
// alert routes, then compiles them into the runtime IR carried by
// RuntimePolicyPack.
package response

import (
	"fmt"
	"os"
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	registries "github.com/kernloom/kernloom-registries"
	"gopkg.in/yaml.v3"
)

const (
	KindDetectionPolicy = "DetectionPolicy"
	KindResponsePolicy  = "ResponsePolicy"
	KindAlertRoute      = "AlertRoute"
)

type Metadata struct {
	Name    string `yaml:"name,omitempty"`
	ID      string `yaml:"id,omitempty"`
	Version string `yaml:"version,omitempty"`
}

type Policy struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

type Spec struct {
	Mode               string `yaml:"mode,omitempty"`
	StateRequired      bool   `yaml:"stateRequired,omitempty"`
	ConflictResolution string `yaml:"conflictResolution,omitempty"`
	Rules              []Rule `yaml:"rules"`
}

type Rule struct {
	ID          string                 `yaml:"id"`
	Description string                 `yaml:"description,omitempty"`
	When        Trigger                `yaml:"when"`
	Then        ActionHolder           `yaml:"then"`
	Require     ResponseRequirementSet `yaml:"require,omitempty"`
	ReasonCodes []string               `yaml:"reasonCodes,omitempty"`
}

type ResponseRequirementSet struct {
	PreviousAction *PreviousActionRequirement `yaml:"previousAction,omitempty"`
	BlastRadius    *BlastRadiusRequirement    `yaml:"blastRadius,omitempty"`
}

type PreviousActionRequirement struct {
	ID       string   `yaml:"id"`
	Active   bool     `yaml:"active"`
	Evidence []string `yaml:"evidence,omitempty"`
}

type BlastRadiusRequirement struct {
	Excludes        []ProtectedSubject `yaml:"excludes,omitempty"`
	UnknownBehavior string             `yaml:"unknownBehavior,omitempty"`
}

type ProtectedSubject struct {
	Type string `yaml:"type"`
	Ref  string `yaml:"ref"`
}

type Trigger struct {
	Type        string         `yaml:"type,omitempty"`
	Detection   string         `yaml:"detection,omitempty"`
	ResourceRef string         `yaml:"resourceRef,omitempty"`
	Threshold   int            `yaml:"threshold,omitempty"`
	Window      string         `yaml:"window,omitempty"`
	Scope       string         `yaml:"scope,omitempty"`
	Params      map[string]any `yaml:"params,omitempty"`
}

type ActionHolder struct {
	Action Action `yaml:"action"`
}

type Action struct {
	ID       string         `yaml:"id"`
	Route    string         `yaml:"route,omitempty"`
	Severity string         `yaml:"severity,omitempty"`
	Dedupe   string         `yaml:"dedupe,omitempty"`
	TTL      string         `yaml:"ttl,omitempty"`
	Target   Target         `yaml:"target,omitempty"`
	Params   map[string]any `yaml:"params,omitempty"`
}

type Target struct {
	Scope string `yaml:"scope,omitempty"`
	Ref   string `yaml:"ref,omitempty"`
}

type AlertRoute struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       string         `yaml:"kind"`
	Metadata   Metadata       `yaml:"metadata"`
	Spec       AlertRouteSpec `yaml:"spec"`
}

type DetectionPolicy struct {
	APIVersion string        `yaml:"apiVersion"`
	Kind       string        `yaml:"kind"`
	Metadata   Metadata      `yaml:"metadata"`
	Spec       DetectionSpec `yaml:"spec"`
}

type DetectionSpec struct {
	Evaluator DetectionEvaluatorSpec `yaml:"evaluator,omitempty"`
	Rules     []DetectionRule        `yaml:"rules"`
}

type DetectionEvaluatorSpec struct {
	Type              string   `yaml:"type,omitempty"`
	StateRequired     bool     `yaml:"stateRequired,omitempty"`
	PreferredRuntimes []string `yaml:"preferredRuntimes,omitempty"`
	AllowedRuntimes   []string `yaml:"allowedRuntimes,omitempty"`
}

type DetectionRule struct {
	ID          string        `yaml:"id"`
	Description string        `yaml:"description,omitempty"`
	When        DetectionWhen `yaml:"when"`
	ReasonCodes []string      `yaml:"reasonCodes,omitempty"`
}

type DetectionWhen struct {
	Type           string           `yaml:"type"`
	Subject        DetectionSubject `yaml:"subject,omitempty"`
	ResourceRef    string           `yaml:"resourceRef,omitempty"`
	Threshold      int              `yaml:"threshold,omitempty"`
	Window         string           `yaml:"window,omitempty"`
	Scope          string           `yaml:"scope,omitempty"`
	GroupBy        []string         `yaml:"groupBy,omitempty"`
	MissingContext string           `yaml:"missingContext,omitempty"`
	Params         map[string]any   `yaml:"params,omitempty"`
}

type DetectionSubject struct {
	Type     string `yaml:"type,omitempty"`
	Ref      string `yaml:"ref,omitempty"`
	Selector string `yaml:"selector,omitempty"`
}

type AlertRouteSpec struct {
	Audience        Audience          `yaml:"audience,omitempty"`
	Channels        []Channel         `yaml:"channels,omitempty"`
	DefaultSeverity string            `yaml:"defaultSeverity,omitempty"`
	Deduplication   Deduplication     `yaml:"deduplication,omitempty"`
	CaseManagement  CaseManagement    `yaml:"caseManagement,omitempty"`
	Acknowledgement Acknowledgment    `yaml:"acknowledgement,omitempty"`
	Meta            map[string]string `yaml:"meta,omitempty"`
}

type Audience struct {
	Type string `yaml:"type,omitempty"`
	Ref  string `yaml:"ref,omitempty"`
}

type Channel struct {
	Type string `yaml:"type,omitempty"`
	Ref  string `yaml:"ref,omitempty"`
}

type Deduplication struct {
	Enabled bool     `yaml:"enabled,omitempty"`
	Window  string   `yaml:"window,omitempty"`
	Keys    []string `yaml:"keys,omitempty"`
}

type CaseManagement struct {
	CreateCase bool   `yaml:"createCase,omitempty"`
	System     string `yaml:"system,omitempty"`
}

type Acknowledgment struct {
	Required     bool         `yaml:"required,omitempty"`
	Timeout      string       `yaml:"timeout,omitempty"`
	NoEscalation bool         `yaml:"noEscalation,omitempty"`
	Escalation   []Escalation `yaml:"escalation,omitempty"`
}

type Escalation struct {
	To  Audience `yaml:"to,omitempty"`
	Via []string `yaml:"via,omitempty"`
}

func LoadPolicyFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing ResponsePolicy %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid ResponsePolicy %s: %w", path, err)
	}
	return &p, nil
}

func LoadDetectionPolicyFromFile(path string) (*DetectionPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var p DetectionPolicy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing DetectionPolicy %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid DetectionPolicy %s: %w", path, err)
	}
	return &p, nil
}

func LoadAlertRouteFromFile(path string) (*AlertRoute, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var route AlertRoute
	if err := yaml.Unmarshal(data, &route); err != nil {
		return nil, fmt.Errorf("parsing AlertRoute %s: %w", path, err)
	}
	if err := route.Validate(); err != nil {
		return nil, fmt.Errorf("invalid AlertRoute %s: %w", path, err)
	}
	return &route, nil
}

func (p *DetectionPolicy) Validate() error {
	if p.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if p.Kind != KindDetectionPolicy {
		return fmt.Errorf("kind must be %s, got %q", KindDetectionPolicy, p.Kind)
	}
	if p.Metadata.Name == "" && p.Metadata.ID == "" {
		return fmt.Errorf("metadata.name or metadata.id is required")
	}
	p.applyDetectionDefaults()
	snapshot := embeddedSnapshot()
	if err := validateDetectionEvaluator(p.Spec.Evaluator); err != nil {
		return err
	}
	if len(p.Spec.Rules) == 0 {
		return fmt.Errorf("spec.rules must not be empty")
	}
	for i, rule := range p.Spec.Rules {
		if rule.ID == "" {
			return fmt.Errorf("spec.rules[%d].id is required", i)
		}
		if rule.When.Type == "" {
			return fmt.Errorf("spec.rules[%d] (%s): when.type is required", i, rule.ID)
		}
		if rule.When.Threshold < 0 {
			return fmt.Errorf("spec.rules[%d] (%s): when.threshold must not be negative", i, rule.ID)
		}
		if rule.When.Window != "" {
			if _, err := time.ParseDuration(rule.When.Window); err != nil {
				return fmt.Errorf("spec.rules[%d] (%s): when.window: %w", i, rule.ID, err)
			}
		}
		if p.Spec.Evaluator.Type == "stateless" && rule.When.Window != "" {
			return fmt.Errorf("spec.rules[%d] (%s): stateless evaluator cannot use when.window", i, rule.ID)
		}
		if rule.When.MissingContext != "" && !validDetectionMissingContext(snapshot, rule.When.MissingContext) {
			return fmt.Errorf("spec.rules[%d] (%s): unsupported missingContext %q", i, rule.ID, rule.When.MissingContext)
		}
	}
	return nil
}

func (p *DetectionPolicy) applyDetectionDefaults() {
	if p == nil {
		return
	}
	if p.Spec.Evaluator.Type == "" {
		p.Spec.Evaluator = inferDetectionEvaluator(p.Spec.Rules)
	}
	if p.Spec.Evaluator.Type != "" {
		p.Spec.Evaluator.Type = normalizeRegistryToken(p.Spec.Evaluator.Type)
	}
	if len(p.Spec.Evaluator.AllowedRuntimes) == 0 {
		p.Spec.Evaluator.AllowedRuntimes = defaultEvaluatorRuntimes(p.Spec.Evaluator.Type)
	}
	if len(p.Spec.Evaluator.PreferredRuntimes) == 0 && len(p.Spec.Evaluator.AllowedRuntimes) > 0 {
		p.Spec.Evaluator.PreferredRuntimes = p.Spec.Evaluator.AllowedRuntimes[:1]
	}
	for i := range p.Spec.Rules {
		if len(p.Spec.Rules[i].When.GroupBy) == 0 {
			p.Spec.Rules[i].When.GroupBy = defaultDetectionGroupBy(p.Spec.Rules[i].When.Scope)
		}
		if p.Spec.Rules[i].When.MissingContext == "" {
			p.Spec.Rules[i].When.MissingContext = "not_match"
		}
	}
}

func inferDetectionEvaluator(rules []DetectionRule) DetectionEvaluatorSpec {
	stateRequired := false
	externalOnly := len(rules) > 0
	for _, rule := range rules {
		if rule.When.Window != "" || rule.When.Threshold > 1 {
			stateRequired = true
		}
		switch rule.When.Type {
		case "access.denied_threshold", "source.rate_limit_drops_sustained", "network.rate_limit_drop_threshold":
			stateRequired = true
			externalOnly = false
		case "signal.threshold", "signal.score_threshold":
		default:
			externalOnly = false
		}
	}
	if stateRequired {
		return DetectionEvaluatorSpec{Type: "windowed", StateRequired: true}
	}
	if externalOnly {
		return DetectionEvaluatorSpec{Type: "external_signal", StateRequired: false}
	}
	return DetectionEvaluatorSpec{Type: "stateless", StateRequired: false}
}

func inferRuntimeDetectionEvaluator(rules []contracts.RuntimeDetectionRule) DetectionEvaluatorSpec {
	stateRequired := false
	externalOnly := len(rules) > 0
	for _, rule := range rules {
		if rule.Window.Duration > 0 || rule.Threshold > 1 {
			stateRequired = true
		}
		switch rule.Type {
		case "access.denied_threshold", "source.rate_limit_drops_sustained", "network.rate_limit_drop_threshold":
			stateRequired = true
			externalOnly = false
		case "signal.threshold", "signal.score_threshold":
		default:
			externalOnly = false
		}
	}
	if stateRequired {
		return DetectionEvaluatorSpec{Type: "windowed", StateRequired: true, AllowedRuntimes: defaultEvaluatorRuntimes("windowed"), PreferredRuntimes: []string{"kliq-local-windowed"}}
	}
	if externalOnly {
		return DetectionEvaluatorSpec{Type: "external_signal", StateRequired: false, AllowedRuntimes: defaultEvaluatorRuntimes("external_signal"), PreferredRuntimes: []string{"kliq-signal"}}
	}
	return DetectionEvaluatorSpec{Type: "stateless", StateRequired: false, AllowedRuntimes: defaultEvaluatorRuntimes("stateless"), PreferredRuntimes: []string{"kliq-local-stateless"}}
}

func validateDetectionEvaluator(e DetectionEvaluatorSpec) error {
	if e.Type == "" {
		return fmt.Errorf("spec.evaluator.type is required")
	}
	snapshot := embeddedSnapshot()
	if !validDetectionEvaluatorType(snapshot, e.Type) {
		return fmt.Errorf("spec.evaluator.type %q is not supported", e.Type)
	}
	if entry, ok := detectionEvaluatorEntry(snapshot, e.Type); ok && entry.StateRequired && !e.StateRequired {
		return fmt.Errorf("spec.evaluator.stateRequired must be true for evaluator %q", e.Type)
	}
	if e.Type == "stateless" && e.StateRequired {
		return fmt.Errorf("spec.evaluator.stateRequired cannot be true for stateless evaluator")
	}
	return nil
}

func validDetectionEvaluatorType(snapshot contracts.RegistrySnapshot, value string) bool {
	if _, ok := detectionEvaluatorEntry(snapshot, value); ok {
		return true
	}
	if len(snapshot.DetectionEvaluators) > 0 {
		return false
	}
	return fallbackToken(value, "stateless", "windowed", "stateful_sequence", "external_signal")
}

func detectionEvaluatorEntry(snapshot contracts.RegistrySnapshot, value string) (contracts.DetectionEvaluatorEntry, bool) {
	value = normalizeRegistryToken(value)
	for _, entry := range snapshot.DetectionEvaluators {
		if normalizeRegistryToken(entry.ID) == value {
			return entry, true
		}
	}
	return contracts.DetectionEvaluatorEntry{}, false
}

func validDetectionMissingContext(snapshot contracts.RegistrySnapshot, value string) bool {
	if policyVocabularyContains(snapshot.MissingContextBehaviors, value, "DetectionPolicy") {
		return true
	}
	if len(snapshot.MissingContextBehaviors) > 0 {
		return false
	}
	return fallbackToken(value, "not_match", "degrade_to_alert", "require_review", "fail_validation")
}

func defaultEvaluatorRuntimes(evaluator string) []string {
	switch normalizeRegistryToken(evaluator) {
	case "windowed":
		return []string{"kliq-local-windowed", "correlate"}
	case "stateful_sequence":
		return []string{"kliq-local-stateful", "correlate"}
	case "external_signal":
		return []string{"kliq-signal", "correlate"}
	default:
		return []string{"kliq-local-stateless", "correlate"}
	}
}

func defaultDetectionGroupBy(scope string) []string {
	switch normalizeRegistryToken(scope) {
	case "subject":
		return []string{"subject.id"}
	case "resource":
		return []string{"resource.id"}
	case "source", "":
		return []string{"source.identity_or_ip"}
	default:
		return []string{scope}
	}
}

func runtimeDetectionParams(when DetectionWhen, evaluator DetectionEvaluatorSpec) map[string]any {
	params := copyAnyMap(when.Params)
	if params == nil {
		params = map[string]any{}
	}
	if len(when.GroupBy) > 0 {
		params["group_by"] = append([]string(nil), when.GroupBy...)
	}
	if when.MissingContext != "" {
		params["missing_context"] = when.MissingContext
	}
	if evaluator.Type != "" {
		params["evaluator_type"] = evaluator.Type
		params["evaluator_state_required"] = evaluator.StateRequired
	}
	if len(evaluator.AllowedRuntimes) > 0 {
		params["allowed_runtimes"] = append([]string(nil), evaluator.AllowedRuntimes...)
	}
	if len(params) == 0 {
		return nil
	}
	return params
}

func normalizeRegistryToken(value string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_")
}

func embeddedSnapshot() contracts.RegistrySnapshot {
	snapshot, err := registries.EmbeddedSnapshot()
	if err != nil {
		return contracts.RegistrySnapshot{}
	}
	return snapshot
}

func policyVocabularyContains(entries []contracts.PolicyVocabularyEntry, value, appliesTo string) bool {
	value = normalizeRegistryToken(value)
	for _, entry := range entries {
		if normalizeRegistryToken(entry.ID) != value {
			continue
		}
		if appliesTo == "" || len(entry.AppliesTo) == 0 {
			return true
		}
		for _, item := range entry.AppliesTo {
			if item == appliesTo {
				return true
			}
		}
	}
	return false
}

func fallbackToken(value string, allowed ...string) bool {
	value = normalizeRegistryToken(value)
	for _, item := range allowed {
		if normalizeRegistryToken(item) == value {
			return true
		}
	}
	return false
}

func (p *Policy) Validate() error {
	if p.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if p.Kind != KindResponsePolicy {
		return fmt.Errorf("kind must be %s, got %q", KindResponsePolicy, p.Kind)
	}
	if p.Metadata.Name == "" && p.Metadata.ID == "" {
		return fmt.Errorf("metadata.name or metadata.id is required")
	}
	if len(p.Spec.Rules) == 0 {
		return fmt.Errorf("spec.rules must not be empty")
	}
	for i, rule := range p.Spec.Rules {
		if rule.ID == "" {
			return fmt.Errorf("spec.rules[%d].id is required", i)
		}
		if rule.When.Type == "" && rule.When.Detection == "" {
			return fmt.Errorf("spec.rules[%d] (%s): when.type or when.detection is required", i, rule.ID)
		}
		if rule.Then.Action.ID == "" {
			return fmt.Errorf("spec.rules[%d] (%s): then.action.id is required", i, rule.ID)
		}
		if rule.Then.Action.ID == "notify.alert.emit" && rule.Then.Action.Route == "" {
			return fmt.Errorf("spec.rules[%d] (%s): notify.alert.emit requires route", i, rule.ID)
		}
		if err := validateResponseRequirements(rule.Require); err != nil {
			return fmt.Errorf("spec.rules[%d] (%s): require: %w", i, rule.ID, err)
		}
	}
	return nil
}

func (route *AlertRoute) Validate() error {
	if route.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if route.Kind != KindAlertRoute {
		return fmt.Errorf("kind must be %s, got %q", KindAlertRoute, route.Kind)
	}
	if route.ID() == "" {
		return fmt.Errorf("metadata.name or metadata.id is required")
	}
	if route.Spec.Audience.Ref == "" && len(route.Spec.Channels) == 0 {
		return fmt.Errorf("spec.audience or spec.channels is required")
	}
	if err := validateAlertRouteBindings(route.Spec); err != nil {
		return err
	}
	if route.Spec.Acknowledgement.Required && route.Spec.Acknowledgement.Timeout == "" {
		return fmt.Errorf("spec.acknowledgement.timeout is required when acknowledgement is required")
	}
	if route.Spec.Acknowledgement.Required && len(route.Spec.Acknowledgement.Escalation) == 0 && !route.Spec.Acknowledgement.NoEscalation {
		return fmt.Errorf("spec.acknowledgement requires escalation or noEscalation")
	}
	return nil
}

func (route *AlertRoute) ID() string {
	if route.Metadata.ID != "" {
		return route.Metadata.ID
	}
	return route.Metadata.Name
}

func (p *Policy) RuntimeResponseRules() ([]contracts.RuntimeResponseRule, error) {
	out := make([]contracts.RuntimeResponseRule, 0, len(p.Spec.Rules))
	for _, rule := range p.Spec.Rules {
		when, err := runtimeTrigger(rule.When)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		action, err := runtimeAction(rule.Then.Action, rule.Require)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		out = append(out, contracts.RuntimeResponseRule{
			ID:          rule.ID,
			Description: rule.Description,
			When:        when,
			Then:        []contracts.RuntimeResponseAction{action},
			ReasonCodes: append([]string(nil), rule.ReasonCodes...),
		})
	}
	return out, nil
}

func (p *DetectionPolicy) RuntimeDetectionRules() ([]contracts.RuntimeDetectionRule, error) {
	p.applyDetectionDefaults()
	out := make([]contracts.RuntimeDetectionRule, 0, len(p.Spec.Rules))
	for _, rule := range p.Spec.Rules {
		window, err := durationOrZero(rule.When.Window)
		if err != nil {
			return nil, fmt.Errorf("rule %s window: %w", rule.ID, err)
		}
		reasons := append([]string(nil), rule.ReasonCodes...)
		if len(reasons) == 0 {
			reasons = []string{"detection_" + sanitizeReason(rule.ID)}
		}
		out = append(out, contracts.RuntimeDetectionRule{
			ID:          rule.ID,
			Description: rule.Description,
			Type:        rule.When.Type,
			Subject: contracts.RuntimeDetectionSubject{
				Type:     rule.When.Subject.Type,
				Ref:      rule.When.Subject.Ref,
				Selector: rule.When.Subject.Selector,
			},
			ResourceRef: rule.When.ResourceRef,
			Threshold:   rule.When.Threshold,
			Window:      window,
			Scope:       rule.When.Scope,
			Params:      runtimeDetectionParams(rule.When, p.Spec.Evaluator),
			ReasonCodes: reasons,
		})
	}
	return out, nil
}

func (route *AlertRoute) RuntimeAlertRoute() (contracts.RuntimeAlertRoute, error) {
	dedupeWindow, err := durationOrZero(route.Spec.Deduplication.Window)
	if err != nil {
		return contracts.RuntimeAlertRoute{}, fmt.Errorf("deduplication.window: %w", err)
	}
	ackTimeout, err := durationOrZero(route.Spec.Acknowledgement.Timeout)
	if err != nil {
		return contracts.RuntimeAlertRoute{}, fmt.Errorf("acknowledgement.timeout: %w", err)
	}
	channels := make([]contracts.RuntimeAlertChannel, 0, len(route.Spec.Channels))
	for _, ch := range route.Spec.Channels {
		channels = append(channels, contracts.RuntimeAlertChannel{Type: ch.Type, Ref: ch.Ref})
	}
	escalations := make([]contracts.RuntimeAlertEscalation, 0, len(route.Spec.Acknowledgement.Escalation))
	for _, escalation := range route.Spec.Acknowledgement.Escalation {
		escalations = append(escalations, contracts.RuntimeAlertEscalation{
			To:  contracts.RuntimeAlertAudience{Type: escalation.To.Type, Ref: escalation.To.Ref},
			Via: append([]string(nil), escalation.Via...),
		})
	}
	return contracts.RuntimeAlertRoute{
		ID: route.ID(),
		Audience: contracts.RuntimeAlertAudience{
			Type: route.Spec.Audience.Type,
			Ref:  route.Spec.Audience.Ref,
		},
		Channels:        channels,
		DefaultSeverity: route.Spec.DefaultSeverity,
		Deduplication: contracts.RuntimeAlertDeduplication{
			Enabled: route.Spec.Deduplication.Enabled,
			Window:  dedupeWindow,
			Keys:    append([]string(nil), route.Spec.Deduplication.Keys...),
		},
		CaseManagement: contracts.RuntimeAlertCaseManagement{
			CreateCase: route.Spec.CaseManagement.CreateCase,
			System:     route.Spec.CaseManagement.System,
		},
		Acknowledgement: contracts.RuntimeAlertAcknowledgement{
			Required:     route.Spec.Acknowledgement.Required,
			Timeout:      ackTimeout,
			NoEscalation: route.Spec.Acknowledgement.NoEscalation,
			Escalation:   escalations,
		},
		Meta: copyStringMap(route.Spec.Meta),
	}, nil
}

func ValidateRuntimeReferences(
	detections []contracts.RuntimeDetectionRule,
	responses []contracts.RuntimeResponseRule,
	routes []contracts.RuntimeAlertRoute,
	snapshot contracts.RegistrySnapshot,
) error {
	detectionIDs := map[string]bool{}
	for _, detection := range detections {
		if detection.ID == "" {
			return fmt.Errorf("detection rule id is required")
		}
		if detectionIDs[detection.ID] {
			return fmt.Errorf("duplicate detection rule %q", detection.ID)
		}
		if detection.Type == "" {
			return fmt.Errorf("detection rule %q type is required", detection.ID)
		}
		if evaluator := stringAnyParam(detection.Params, "evaluator_type"); evaluator != "" && !validDetectionEvaluatorType(snapshot, evaluator) {
			return fmt.Errorf("detection rule %q evaluator_type %q is not supported", detection.ID, evaluator)
		}
		if missing := stringAnyParam(detection.Params, "missing_context"); missing != "" && !validDetectionMissingContext(snapshot, missing) {
			return fmt.Errorf("detection rule %q missing_context %q is not supported", detection.ID, missing)
		}
		detectionIDs[detection.ID] = true
	}
	routeIDs := map[string]bool{}
	for _, route := range routes {
		if route.ID == "" {
			return fmt.Errorf("alert route id is required")
		}
		if routeIDs[route.ID] {
			return fmt.Errorf("duplicate alert route %q", route.ID)
		}
		if route.DefaultSeverity != "" && !validSeverity(route.DefaultSeverity) {
			return fmt.Errorf("alert route %q has unsupported default severity %q", route.ID, route.DefaultSeverity)
		}
		if err := validateRuntimeAlertRouteBindings(route, snapshot); err != nil {
			return fmt.Errorf("alert route %q: %w", route.ID, err)
		}
		if route.Deduplication.Enabled && route.Deduplication.Window.Duration <= 0 {
			return fmt.Errorf("alert route %q has deduplication.enabled without deduplication.window", route.ID)
		}
		if route.CaseManagement.CreateCase && route.CaseManagement.System == "" {
			return fmt.Errorf("alert route %q create_case requires case_management.system", route.ID)
		}
		if route.Acknowledgement.Required && route.Acknowledgement.Timeout.Duration <= 0 {
			return fmt.Errorf("alert route %q acknowledgement requires timeout", route.ID)
		}
		if route.Acknowledgement.Required && len(route.Acknowledgement.Escalation) == 0 && !route.Acknowledgement.NoEscalation {
			return fmt.Errorf("alert route %q acknowledgement requires escalation or no_escalation", route.ID)
		}
		routeIDs[route.ID] = true
	}

	actionContracts := map[string]contracts.RuntimeActionContractEntry{}
	for _, contract := range snapshot.ActionContracts {
		actionContracts[contract.ID] = contract
	}
	capabilities := map[string]contracts.CapabilityEntry{}
	for _, capability := range snapshot.Capabilities {
		capabilities[capability.ID] = capability
	}
	responseIDs := map[string]bool{}
	for _, response := range responses {
		if response.ID == "" {
			return fmt.Errorf("response rule id is required")
		}
		if responseIDs[response.ID] {
			return fmt.Errorf("duplicate response rule %q", response.ID)
		}
		responseIDs[response.ID] = true
		if response.When.Detection != "" && !detectionExists(response.When.Detection, detectionIDs) {
			return fmt.Errorf("response rule %q references unknown detection %q", response.ID, response.When.Detection)
		}
		if len(response.Then) == 0 {
			return fmt.Errorf("response rule %q has no actions", response.ID)
		}
		for i, action := range response.Then {
			if action.ID == "" {
				return fmt.Errorf("response rule %q action[%d] id is required", response.ID, i)
			}
			contract, hasContract := actionContracts[action.ID]
			capability, hasCapability := capabilities[action.ID]
			if len(actionContracts) > 0 && len(capabilities) > 0 && !hasContract && !hasCapability {
				return fmt.Errorf("response rule %q action %q is not in registry snapshot", response.ID, action.ID)
			}
			if action.ID == "notify.alert.emit" {
				if action.Route == "" {
					return fmt.Errorf("response rule %q notify.alert.emit requires route", response.ID)
				}
				if !routeIDs[action.Route] {
					return fmt.Errorf("response rule %q references unknown alert route %q", response.ID, action.Route)
				}
				if action.Severity != "" && !validSeverity(action.Severity) {
					return fmt.Errorf("response rule %q notify.alert.emit has unsupported severity %q", response.ID, action.Severity)
				}
				if action.Dedupe.Duration <= 0 {
					route := routeByID(routes, action.Route)
					if route == nil || route.Deduplication.Window.Duration <= 0 {
						return fmt.Errorf("response rule %q notify.alert.emit requires action dedupe or route deduplication.window", response.ID)
					}
				}
				continue
			}
			if err := validateRuntimeResponseRequirements(action.Params); err != nil {
				return fmt.Errorf("response rule %q action %q: %w", response.ID, action.ID, err)
			}
			if action.TTL.Duration <= 0 {
				return fmt.Errorf("response rule %q action %q requires ttl", response.ID, action.ID)
			}
			if hasCapability && capability.Effect == "grant" {
				return fmt.Errorf("response rule %q action %q grants access and is not allowed in runtime response", response.ID, action.ID)
			}
			if hasContract {
				if contract.CanGrantAccess {
					return fmt.Errorf("response rule %q action %q can grant access and is not allowed in runtime response", response.ID, action.ID)
				}
				if !contract.RuntimeAllowed {
					return fmt.Errorf("response rule %q action %q is not runtime allowed", response.ID, action.ID)
				}
				if contract.RequiresTTL && action.TTL.Duration <= 0 {
					return fmt.Errorf("response rule %q action %q requires ttl", response.ID, action.ID)
				}
				if maxTTL, err := parseOptionalDuration(contract.MaxTTL); err != nil {
					return fmt.Errorf("response rule %q action %q maxTTL: %w", response.ID, action.ID, err)
				} else if maxTTL > 0 && action.TTL.Duration > maxTTL {
					return fmt.Errorf("response rule %q action %q ttl %s exceeds maxTTL %s", response.ID, action.ID, action.TTL.Duration, maxTTL)
				}
			}
		}
	}
	return nil
}

func PolicyFromRuntime(name string, rules []contracts.RuntimeResponseRule) Policy {
	out := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if len(rule.Then) == 0 {
			continue
		}
		require := responseRequirementsFromParams(rule.Then[0].Params)
		out = append(out, Rule{
			ID:          rule.ID,
			Description: rule.Description,
			When: Trigger{
				Type:        rule.When.Type,
				Detection:   rule.When.Detection,
				ResourceRef: rule.When.ResourceRef,
				Threshold:   rule.When.Threshold,
				Window:      rule.When.Window.String(),
				Scope:       rule.When.Scope,
				Params:      rule.When.Params,
			},
			Then: ActionHolder{Action: Action{
				ID:       rule.Then[0].ID,
				Route:    rule.Then[0].Route,
				Severity: rule.Then[0].Severity,
				Dedupe:   durationString(rule.Then[0].Dedupe),
				TTL:      durationString(rule.Then[0].TTL),
				Target: Target{
					Scope: rule.Then[0].Target.Scope,
					Ref:   rule.Then[0].Target.Ref,
				},
				Params: responseActionParamsWithoutRequirements(rule.Then[0].Params),
			}},
			Require:     require,
			ReasonCodes: append([]string(nil), rule.ReasonCodes...),
		})
	}
	return Policy{
		APIVersion: "kernloom.io/v1",
		Kind:       KindResponsePolicy,
		Metadata:   Metadata{Name: name},
		Spec: Spec{
			Mode:               "ordered",
			StateRequired:      true,
			ConflictResolution: "strongest_allowed_action",
			Rules:              out,
		},
	}
}

func routeByID(routes []contracts.RuntimeAlertRoute, id string) *contracts.RuntimeAlertRoute {
	for i := range routes {
		if routes[i].ID == id {
			return &routes[i]
		}
	}
	return nil
}

func detectionExists(ref string, detections map[string]bool) bool {
	if detections[ref] {
		return true
	}
	for id := range detections {
		if strings.HasSuffix(ref, "/"+id) {
			return true
		}
	}
	return false
}

func validSeverity(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func validateResponseRequirements(require ResponseRequirementSet) error {
	if require.PreviousAction != nil {
		if strings.TrimSpace(require.PreviousAction.ID) == "" {
			return fmt.Errorf("previousAction.id is required")
		}
		if !require.PreviousAction.Active {
			return fmt.Errorf("previousAction.active must be true")
		}
		for _, evidence := range require.PreviousAction.Evidence {
			if !validPreviousActionEvidence(evidence) {
				return fmt.Errorf("previousAction.evidence contains unsupported value %q", evidence)
			}
		}
	}
	if require.BlastRadius != nil {
		if require.BlastRadius.UnknownBehavior != "" && !validBlastRadiusUnknownBehavior(require.BlastRadius.UnknownBehavior) {
			return fmt.Errorf("blastRadius.unknownBehavior contains unsupported value %q", require.BlastRadius.UnknownBehavior)
		}
		for i, subject := range require.BlastRadius.Excludes {
			if strings.TrimSpace(subject.Type) == "" || strings.TrimSpace(subject.Ref) == "" {
				return fmt.Errorf("blastRadius.excludes[%d] requires type and ref", i)
			}
		}
	}
	return nil
}

func validateRuntimeResponseRequirements(params map[string]any) error {
	require := responseRequirementsFromParams(params)
	return validateResponseRequirements(require)
}

func responseRequirementParams(require ResponseRequirementSet) map[string]any {
	out := map[string]any{}
	if require.PreviousAction != nil {
		out["previous_action_id"] = strings.TrimSpace(require.PreviousAction.ID)
		out["previous_action_active"] = true
		evidence := normalizePreviousActionEvidence(require.PreviousAction.Evidence)
		if len(evidence) == 0 {
			evidence = []string{"runtime_response_state"}
		}
		out["previous_action_evidence"] = evidence
		if stringSliceContains(evidence, "local_runtime_state") {
			out["allow_local_runtime_state_evidence"] = true
		}
	}
	if require.BlastRadius != nil {
		blast := map[string]any{}
		if len(require.BlastRadius.Excludes) > 0 {
			excludes := make([]map[string]string, 0, len(require.BlastRadius.Excludes))
			for _, subject := range require.BlastRadius.Excludes {
				excludes = append(excludes, map[string]string{
					"type": strings.TrimSpace(subject.Type),
					"ref":  strings.TrimSpace(subject.Ref),
				})
			}
			blast["excludes"] = excludes
			for _, subject := range require.BlastRadius.Excludes {
				if subject.Type == "group" && out["requires_target_excludes_group"] == nil {
					out["requires_target_excludes_group"] = subject.Ref
					out["blast_radius_check"] = "exclude_protected_subject"
				}
			}
		}
		if require.BlastRadius.UnknownBehavior != "" {
			blast["unknown_behavior"] = require.BlastRadius.UnknownBehavior
		}
		out["blast_radius"] = blast
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func responseRequirementsFromParams(params map[string]any) ResponseRequirementSet {
	var require ResponseRequirementSet
	if id := strings.TrimSpace(fmt.Sprint(params["previous_action_id"])); id != "" && id != "<nil>" {
		require.PreviousAction = &PreviousActionRequirement{
			ID:       id,
			Active:   boolAnyParam(params, "previous_action_active"),
			Evidence: normalizePreviousActionEvidence(stringSliceAnyParam(params, "previous_action_evidence")),
		}
		if len(require.PreviousAction.Evidence) == 0 {
			require.PreviousAction.Evidence = []string{"runtime_response_state"}
		}
		if !require.PreviousAction.Active {
			require.PreviousAction.Active = true
		}
	}
	if blast := blastRadiusRequirementFromParams(params); blast != nil {
		require.BlastRadius = blast
	}
	return require
}

func blastRadiusRequirementFromParams(params map[string]any) *BlastRadiusRequirement {
	var out BlastRadiusRequirement
	if raw, ok := params["blast_radius"]; ok {
		if m, ok := raw.(map[string]any); ok {
			out.UnknownBehavior = strings.TrimSpace(fmt.Sprint(m["unknown_behavior"]))
			for _, subject := range protectedSubjectsFromAny(m["excludes"]) {
				out.Excludes = appendProtectedSubjectUnique(out.Excludes, subject)
			}
		}
	}
	if group := strings.TrimSpace(fmt.Sprint(params["requires_target_excludes_group"])); group != "" && group != "<nil>" {
		out.Excludes = appendProtectedSubjectUnique(out.Excludes, ProtectedSubject{Type: "group", Ref: group})
		if out.UnknownBehavior == "" {
			out.UnknownBehavior = "reject_hard_action"
		}
	}
	if len(out.Excludes) == 0 && out.UnknownBehavior == "" {
		return nil
	}
	return &out
}

func appendProtectedSubjectUnique(values []ProtectedSubject, subject ProtectedSubject) []ProtectedSubject {
	subject.Type = strings.TrimSpace(subject.Type)
	subject.Ref = strings.TrimSpace(subject.Ref)
	if subject.Type == "" || subject.Ref == "" {
		return values
	}
	for _, existing := range values {
		if strings.TrimSpace(existing.Type) == subject.Type && strings.TrimSpace(existing.Ref) == subject.Ref {
			return values
		}
	}
	return append(values, subject)
}

func protectedSubjectsFromAny(raw any) []ProtectedSubject {
	var out []ProtectedSubject
	switch values := raw.(type) {
	case []map[string]string:
		for _, item := range values {
			out = append(out, ProtectedSubject{Type: item["type"], Ref: item["ref"]})
		}
	case []map[string]any:
		for _, item := range values {
			out = append(out, ProtectedSubject{Type: fmt.Sprint(item["type"]), Ref: fmt.Sprint(item["ref"])})
		}
	case []any:
		for _, item := range values {
			switch typed := item.(type) {
			case map[string]any:
				out = append(out, ProtectedSubject{Type: fmt.Sprint(typed["type"]), Ref: fmt.Sprint(typed["ref"])})
			case map[string]string:
				out = append(out, ProtectedSubject{Type: typed["type"], Ref: typed["ref"]})
			}
		}
	}
	return out
}

func responseActionParamsWithoutRequirements(params map[string]any) map[string]any {
	out := copyAnyMap(params)
	for _, key := range []string{
		"previous_action_id",
		"previous_action_active",
		"previous_action_evidence",
		"allow_local_runtime_state_evidence",
		"blast_radius",
		"blast_radius_check",
		"requires_target_excludes_group",
	} {
		delete(out, key)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func responseActionParamsWithoutDetectionMeta(params map[string]any) map[string]any {
	out := copyAnyMap(params)
	for _, key := range []string{
		"group_by",
		"missing_context",
		"evaluator_type",
		"evaluator_state_required",
		"allowed_runtimes",
		"preferred_runtimes",
	} {
		delete(out, key)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizePreviousActionEvidence(values []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_")
		switch value {
		case "runtime_response_state":
		case "local_enforcement_state", "local_runtime_state", "local_state":
			value = "local_runtime_state"
		default:
			continue
		}
		if !seen[value] {
			out = append(out, value)
			seen[value] = true
		}
	}
	return out
}

func validPreviousActionEvidence(value string) bool {
	value = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_")
	switch value {
	case "runtime_response_state", "local_enforcement_state", "local_runtime_state", "local_state":
		return true
	default:
		return false
	}
}

func validBlastRadiusUnknownBehavior(value string) bool {
	snapshot := embeddedSnapshot()
	if policyVocabularyContains(snapshot.MissingContextBehaviors, value, "ResponsePolicy") ||
		policyVocabularyContains(snapshot.MissingContextBehaviors, value, "GuardrailPolicy") {
		return true
	}
	if len(snapshot.MissingContextBehaviors) > 0 {
		return false
	}
	return fallbackToken(value, "reject_hard_action", "require_review", "degrade_to_alert", "degrade_to_rate_limit")
}

func validateAlertRouteBindings(spec AlertRouteSpec) error {
	snapshot := embeddedSnapshot()
	if spec.Audience.Ref != "" && spec.Audience.Type == "" {
		return fmt.Errorf("spec.audience.type is required when audience.ref is set")
	}
	for i, ch := range spec.Channels {
		if err := validateAlertChannelBinding(snapshot, ch.Type, ch.Ref); err != nil {
			return fmt.Errorf("spec.channels[%d]: %w", i, err)
		}
	}
	if spec.CaseManagement.CreateCase && spec.CaseManagement.System != "" && !validCaseManagementSystem(snapshot, spec.CaseManagement.System) {
		return fmt.Errorf("spec.caseManagement.system %q is not a registered binding", spec.CaseManagement.System)
	}
	for i, escalation := range spec.Acknowledgement.Escalation {
		if escalation.To.Ref != "" && escalation.To.Type == "" {
			return fmt.Errorf("spec.acknowledgement.escalation[%d].to.type is required when to.ref is set", i)
		}
		for _, via := range escalation.Via {
			if !validAlertChannelType(snapshot, via) {
				return fmt.Errorf("spec.acknowledgement.escalation[%d].via contains unsupported channel %q", i, via)
			}
		}
	}
	return nil
}

func validateRuntimeAlertRouteBindings(route contracts.RuntimeAlertRoute, snapshot contracts.RegistrySnapshot) error {
	if route.Audience.Ref != "" && route.Audience.Type == "" {
		return fmt.Errorf("audience.type is required when audience.ref is set")
	}
	for i, ch := range route.Channels {
		if err := validateAlertChannelBinding(snapshot, ch.Type, ch.Ref); err != nil {
			return fmt.Errorf("channels[%d]: %w", i, err)
		}
	}
	if route.CaseManagement.CreateCase && route.CaseManagement.System != "" && !validCaseManagementSystem(snapshot, route.CaseManagement.System) {
		return fmt.Errorf("case_management.system %q is not a registered binding", route.CaseManagement.System)
	}
	for i, escalation := range route.Acknowledgement.Escalation {
		if escalation.To.Ref != "" && escalation.To.Type == "" {
			return fmt.Errorf("acknowledgement.escalation[%d].to.type is required when to.ref is set", i)
		}
		for _, via := range escalation.Via {
			if !validAlertChannelType(snapshot, via) {
				return fmt.Errorf("acknowledgement.escalation[%d].via contains unsupported channel %q", i, via)
			}
		}
	}
	return nil
}

func validateAlertChannelBinding(snapshot contracts.RegistrySnapshot, channelType, ref string) error {
	channelType = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(channelType)), "-", "_")
	ref = strings.TrimSpace(ref)
	if channelType == "" {
		return fmt.Errorf("type is required")
	}
	if !validAlertChannelType(snapshot, channelType) {
		return fmt.Errorf("unsupported channel type %q", channelType)
	}
	if ref == "" {
		return fmt.Errorf("ref is required")
	}
	for _, prefix := range alertChannelRefPrefixes(snapshot, channelType) {
		if strings.HasPrefix(ref, prefix) {
			return nil
		}
	}
	return fmt.Errorf("ref %q is not a registered %s binding", ref, channelType)
}

func validAlertChannelType(snapshot contracts.RegistrySnapshot, value string) bool {
	value = normalizeRegistryToken(value)
	for _, channel := range snapshot.NotificationBindings.Channels {
		if normalizeRegistryToken(channel.ID) == value {
			return true
		}
	}
	if len(snapshot.NotificationBindings.Channels) > 0 {
		return false
	}
	return fallbackToken(value, "log", "email")
}

func alertChannelRefPrefixes(snapshot contracts.RegistrySnapshot, channelType string) []string {
	channelType = normalizeRegistryToken(channelType)
	for _, channel := range snapshot.NotificationBindings.Channels {
		if normalizeRegistryToken(channel.ID) == channelType {
			return append([]string(nil), channel.RefPrefixes...)
		}
	}
	switch channelType {
	case "log":
		return []string{"log.", "stdout", "stderr"}
	case "email":
		return []string{"channel.", "mailinglist.", "email."}
	default:
		return nil
	}
}

func validCaseManagementSystem(snapshot contracts.RegistrySnapshot, value string) bool {
	value = normalizeRegistryToken(value)
	for _, system := range snapshot.NotificationBindings.CaseSystems {
		if normalizeRegistryToken(system.ID) == value {
			return true
		}
	}
	if len(snapshot.NotificationBindings.CaseSystems) > 0 {
		return strings.HasPrefix(value, "case.") || strings.HasPrefix(value, "incident.")
	}
	switch {
	case value == "incident_backend", value == "case_backend", value == "servicenow", value == "jira":
		return true
	case strings.HasPrefix(value, "case."), strings.HasPrefix(value, "incident."):
		return true
	default:
		return false
	}
}

func boolAnyParam(params map[string]any, key string) bool {
	value, ok := params[key]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		typed = strings.ToLower(strings.TrimSpace(typed))
		return typed == "true" || typed == "yes" || typed == "1"
	default:
		return fmt.Sprint(typed) == "true"
	}
}

func stringAnyParam(params map[string]any, key string) string {
	if len(params) == 0 {
		return ""
	}
	value, ok := params[key]
	if !ok {
		return ""
	}
	valueString := strings.TrimSpace(fmt.Sprint(value))
	if valueString == "<nil>" {
		return ""
	}
	return valueString
}

func stringSliceAnyParam(params map[string]any, key string) []string {
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
		var out []string
		for _, part := range strings.Split(typed, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
		return out
	default:
		return []string{fmt.Sprint(typed)}
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func parseOptionalDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	return time.ParseDuration(value)
}

func DetectionPolicyFromRuntime(name string, rules []contracts.RuntimeDetectionRule) DetectionPolicy {
	out := make([]DetectionRule, 0, len(rules))
	for _, rule := range rules {
		params := responseActionParamsWithoutDetectionMeta(rule.Params)
		groupBy := stringSliceAnyParam(rule.Params, "group_by")
		missingContext := stringAnyParam(rule.Params, "missing_context")
		out = append(out, DetectionRule{
			ID:          rule.ID,
			Description: rule.Description,
			When: DetectionWhen{
				Type: rule.Type,
				Subject: DetectionSubject{
					Type:     rule.Subject.Type,
					Ref:      rule.Subject.Ref,
					Selector: rule.Subject.Selector,
				},
				ResourceRef:    rule.ResourceRef,
				Threshold:      rule.Threshold,
				Window:         durationString(rule.Window),
				Scope:          rule.Scope,
				GroupBy:        groupBy,
				MissingContext: missingContext,
				Params:         params,
			},
			ReasonCodes: append([]string(nil), rule.ReasonCodes...),
		})
	}
	return DetectionPolicy{
		APIVersion: "kernloom.io/v1",
		Kind:       KindDetectionPolicy,
		Metadata:   Metadata{Name: name},
		Spec: DetectionSpec{
			Evaluator: inferRuntimeDetectionEvaluator(rules),
			Rules:     out,
		},
	}
}

func AlertRouteFromRuntime(route contracts.RuntimeAlertRoute) AlertRoute {
	channels := make([]Channel, 0, len(route.Channels))
	for _, ch := range route.Channels {
		channels = append(channels, Channel{Type: ch.Type, Ref: ch.Ref})
	}
	escalations := make([]Escalation, 0, len(route.Acknowledgement.Escalation))
	for _, escalation := range route.Acknowledgement.Escalation {
		escalations = append(escalations, Escalation{
			To:  Audience{Type: escalation.To.Type, Ref: escalation.To.Ref},
			Via: append([]string(nil), escalation.Via...),
		})
	}
	return AlertRoute{
		APIVersion: "kernloom.io/v1",
		Kind:       KindAlertRoute,
		Metadata:   Metadata{Name: route.ID},
		Spec: AlertRouteSpec{
			Audience:        Audience{Type: route.Audience.Type, Ref: route.Audience.Ref},
			Channels:        channels,
			DefaultSeverity: route.DefaultSeverity,
			Deduplication: Deduplication{
				Enabled: route.Deduplication.Enabled,
				Window:  durationString(route.Deduplication.Window),
				Keys:    append([]string(nil), route.Deduplication.Keys...),
			},
			CaseManagement: CaseManagement{
				CreateCase: route.CaseManagement.CreateCase,
				System:     route.CaseManagement.System,
			},
			Acknowledgement: Acknowledgment{
				Required:     route.Acknowledgement.Required,
				Timeout:      durationString(route.Acknowledgement.Timeout),
				NoEscalation: route.Acknowledgement.NoEscalation,
				Escalation:   escalations,
			},
			Meta: copyStringMap(route.Meta),
		},
	}
}

func runtimeTrigger(trigger Trigger) (contracts.RuntimeResponseTrigger, error) {
	window, err := durationOrZero(trigger.Window)
	if err != nil {
		return contracts.RuntimeResponseTrigger{}, fmt.Errorf("window: %w", err)
	}
	return contracts.RuntimeResponseTrigger{
		Type:        trigger.Type,
		Detection:   trigger.Detection,
		ResourceRef: trigger.ResourceRef,
		Threshold:   trigger.Threshold,
		Window:      window,
		Scope:       trigger.Scope,
		Params:      trigger.Params,
	}, nil
}

func sanitizeReason(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var out strings.Builder
	lastUnderscore := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			out.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			out.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(out.String(), "_")
}

func runtimeAction(action Action, require ResponseRequirementSet) (contracts.RuntimeResponseAction, error) {
	dedupe, err := durationOrZero(action.Dedupe)
	if err != nil {
		return contracts.RuntimeResponseAction{}, fmt.Errorf("dedupe: %w", err)
	}
	ttl, err := durationOrZero(action.TTL)
	if err != nil {
		return contracts.RuntimeResponseAction{}, fmt.Errorf("ttl: %w", err)
	}
	params := copyAnyMap(action.Params)
	if requirementParams := responseRequirementParams(require); len(requirementParams) > 0 {
		if params == nil {
			params = map[string]any{}
		}
		for key, value := range requirementParams {
			params[key] = value
		}
	}
	return contracts.RuntimeResponseAction{
		ID:       action.ID,
		Route:    action.Route,
		Severity: action.Severity,
		Dedupe:   dedupe,
		TTL:      ttl,
		Target: contracts.RuntimeResponseTarget{
			Scope: action.Target.Scope,
			Ref:   action.Target.Ref,
		},
		Params: params,
	}, nil
}

func durationOrZero(value string) (contracts.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return contracts.Duration{}, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return contracts.Duration{}, err
	}
	return contracts.NewDuration(d), nil
}

func durationString(value contracts.Duration) string {
	if value.IsZero() {
		return ""
	}
	return value.String()
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
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
