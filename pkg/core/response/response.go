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
	ID          string       `yaml:"id"`
	Description string       `yaml:"description,omitempty"`
	When        Trigger      `yaml:"when"`
	Then        ActionHolder `yaml:"then"`
	ReasonCodes []string     `yaml:"reasonCodes,omitempty"`
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
	Rules []DetectionRule `yaml:"rules"`
}

type DetectionRule struct {
	ID          string        `yaml:"id"`
	Description string        `yaml:"description,omitempty"`
	When        DetectionWhen `yaml:"when"`
	ReasonCodes []string      `yaml:"reasonCodes,omitempty"`
}

type DetectionWhen struct {
	Type        string           `yaml:"type"`
	Subject     DetectionSubject `yaml:"subject,omitempty"`
	ResourceRef string           `yaml:"resourceRef,omitempty"`
	Threshold   int              `yaml:"threshold,omitempty"`
	Window      string           `yaml:"window,omitempty"`
	Scope       string           `yaml:"scope,omitempty"`
	Params      map[string]any   `yaml:"params,omitempty"`
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
	}
	return nil
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
		action, err := runtimeAction(rule.Then.Action)
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
			Params:      rule.When.Params,
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

func PolicyFromRuntime(name string, rules []contracts.RuntimeResponseRule) Policy {
	out := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if len(rule.Then) == 0 {
			continue
		}
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
				Params: rule.Then[0].Params,
			}},
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

func DetectionPolicyFromRuntime(name string, rules []contracts.RuntimeDetectionRule) DetectionPolicy {
	out := make([]DetectionRule, 0, len(rules))
	for _, rule := range rules {
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
				ResourceRef: rule.ResourceRef,
				Threshold:   rule.Threshold,
				Window:      durationString(rule.Window),
				Scope:       rule.Scope,
				Params:      rule.Params,
			},
			ReasonCodes: append([]string(nil), rule.ReasonCodes...),
		})
	}
	return DetectionPolicy{
		APIVersion: "kernloom.io/v1",
		Kind:       KindDetectionPolicy,
		Metadata:   Metadata{Name: name},
		Spec:       DetectionSpec{Rules: out},
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

func runtimeAction(action Action) (contracts.RuntimeResponseAction, error) {
	dedupe, err := durationOrZero(action.Dedupe)
	if err != nil {
		return contracts.RuntimeResponseAction{}, fmt.Errorf("dedupe: %w", err)
	}
	ttl, err := durationOrZero(action.TTL)
	if err != nil {
		return contracts.RuntimeResponseAction{}, fmt.Errorf("ttl: %w", err)
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
		Params: action.Params,
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
