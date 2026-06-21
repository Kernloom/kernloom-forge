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
)

type Options struct {
	Name                string
	Owner               string
	DefaultSubjectType  string
	DefaultResourceType string
}

type Result struct {
	Policy        *intent.AccessPolicy
	Guardrails    []contracts.RuntimeGuardrail
	ResponseRules []contracts.RuntimeResponseRule
	Warnings      []string
}

func Convert(data []byte, opts Options) (*Result, error) {
	if opts.DefaultSubjectType == "" {
		opts.DefaultSubjectType = "group"
	}
	if opts.DefaultResourceType == "" {
		opts.DefaultResourceType = "endpoint"
	}

	var (
		resourceType string
		resourceRef  string
		subjectType  string
		subjectRef   string
		environment  string
		conditions   []intent.Condition
		conditionIDs map[string]int
		guardrails   []contracts.RuntimeGuardrail
		responses    []contracts.RuntimeResponseRule
		warnings     []string
	)
	conditionIDs = map[string]int{}

	for lineNo, raw := range strings.Split(string(data), "\n") {
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

		switch tokens[0] {
		case "protect":
			refTokens, envTokens := splitOptionalIn(tokens[1:])
			if len(refTokens) == 0 {
				return nil, fmt.Errorf("line %d: protect requires a resource", lineNo+1)
			}
			resourceType, resourceRef = parseResource(refTokens, opts.DefaultResourceType)
			if len(envTokens) > 0 {
				environment = strings.Join(envTokens, " ")
			}
		case "allow":
			subjTokens, resTokens, err := splitAccessStatement(tokens[1:])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo+1, err)
			}
			subjectType, subjectRef = parseSubject(subjTokens, opts.DefaultSubjectType)
			if len(resTokens) > 0 {
				resourceType, resourceRef = parseResource(resTokens, opts.DefaultResourceType)
			}
		case "require":
			condition, err := parseRequire(tokens[1:])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo+1, err)
			}
			condition.ID = uniqueConditionID(conditionIDs, "require-"+slug(condition.Signal))
			conditions = append(conditions, condition)
		case "deny":
			warnings = append(warnings, fmt.Sprintf("line %d: deny statements are not emitted yet; use target default deny or RuntimePolicyPack default_effect", lineNo+1))
		case "default":
			if len(tokens) >= 2 && tokens[1] == "deny" {
				warnings = append(warnings, fmt.Sprintf("line %d: default deny is represented later as target default behavior or RuntimePolicyPack default_effect", lineNo+1))
				continue
			}
			return nil, fmt.Errorf("line %d: unsupported default statement %q", lineNo+1, line)
		case "when":
			rule, err := parseWhen(tokens[1:])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo+1, err)
			}
			if rule.ResourceRef != "" {
				runtimeRule := rule.RuntimeRule()
				responses = append(responses, runtimeRule)
				action := runtimeRule.Then[0]
				warning := fmt.Sprintf("line %d: response rule %q is emitted as ResponsePolicy IR, not into AccessPolicy", lineNo+1, runtimeRule.ID)
				if action.ID == "notify.alert.emit" {
					warning += fmt.Sprintf(" (alert route %q severity %q dedupe %s)", action.Route, action.Severity, action.Dedupe)
				}
				warnings = append(warnings, warning)
				continue
			}
			warnings = append(warnings, fmt.Sprintf("line %d: when/then response rules are not emitted into AccessPolicy yet", lineNo+1))
		case "never":
			g, err := guardrail.FromNeverTokens(tokens[1:])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo+1, err)
			}
			guardrails = append(guardrails, g)
			warnings = append(warnings, fmt.Sprintf("line %d: never guardrail %q is emitted as runtime guardrail, not into AccessPolicy", lineNo+1, g.ID))
		case "max":
			if len(tokens) >= 2 && tokens[1] == "action" {
				warnings = append(warnings, fmt.Sprintf("line %d: max action guardrails are not emitted into AccessPolicy yet", lineNo+1))
				continue
			}
			return nil, fmt.Errorf("line %d: unsupported max statement %q", lineNo+1, line)
		case "unless":
			warnings = append(warnings, fmt.Sprintf("line %d: unless exceptions are not emitted into AccessPolicy yet", lineNo+1))
		default:
			return nil, fmt.Errorf("line %d: unsupported statement %q", lineNo+1, tokens[0])
		}
	}

	if resourceRef == "" {
		return nil, fmt.Errorf("intent must contain a protected or accessed resource")
	}
	if subjectType == "" {
		subjectType = "any"
	}

	name := opts.Name
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
	if err := pol.Validate(); err != nil {
		return nil, err
	}
	return &Result{Policy: pol, Guardrails: guardrails, ResponseRules: responses, Warnings: warnings}, nil
}

type responseRule struct {
	ResourceRef string
	Threshold   int
	Window      time.Duration
	Action      contracts.RuntimeResponseAction
}

func (r responseRule) RuntimeRule() contracts.RuntimeResponseRule {
	actionSlug := slug(r.Action.ID)
	if r.Action.Route != "" {
		actionSlug = slug(r.Action.Route)
	}
	return contracts.RuntimeResponseRule{
		ID: "denied-access-" + slug(r.ResourceRef) + "-" + actionSlug,
		When: contracts.RuntimeResponseTrigger{
			Type:        "access.denied_threshold",
			ResourceRef: r.ResourceRef,
			Threshold:   r.Threshold,
			Window:      contracts.NewDuration(r.Window),
		},
		Then: []contracts.RuntimeResponseAction{r.Action},
		ReasonCodes: []string{
			"denied_access_threshold_exceeded",
		},
	}
}

func parseWhen(tokens []string) (responseRule, error) {
	if len(tokens) == 0 {
		return responseRule{}, fmt.Errorf("when requires a condition")
	}
	if len(tokens) < 3 || tokens[0] != "denied" || tokens[1] != "access" || tokens[2] != "to" {
		return responseRule{}, nil
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
		ResourceRef: strings.Join(tokens[3:exceedsIndex], " "),
		Threshold:   threshold,
		Window:      windowDuration,
		Action:      action,
	}, nil
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
	operator := tokens[opIndex]
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
	case "subject risk", "subject risk level":
		return "subject.risk.level"
	case "device risk", "device risk level":
		return "device.risk.level"
	case "session risk", "session risk level":
		return "session.risk.level"
	case "device posture", "device posture status":
		return "device.posture.status"
	case "session authentication", "session authentication strength":
		return "session.authentication.strength"
	case "network source":
		return "network.source"
	case "network destination":
		return "network.destination"
	case "network protocol":
		return "network.protocol"
	case "network port":
		return "network.port"
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
	actionTokens, ttl, err := splitOptionalActionTTL(tokens)
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
	if ttl != "" {
		parsed, err := parseDurationToken(ttl)
		if err != nil {
			return contracts.RuntimeResponseAction{}, fmt.Errorf("then action TTL: %w", err)
		}
		runtimeAction.TTL = contracts.NewDuration(parsed)
	}
	return runtimeAction, nil
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
		return action, "enforce.network.rate_limit"
	case "connection_limit":
		return action, "enforce.traffic.connection_limit"
	case "bandwidth_limit":
		return action, "enforce.traffic.bandwidth_limit"
	case "syn_protect":
		return action, "enforce.network.syn_protect"
	case "deny", "block":
		return action, "enforce.access.deny"
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
	case "eq", "neq", "gte", "lte", "gt", "lt", "in", "not_in":
		return true
	default:
		return false
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

func splitOptionalIn(tokens []string) ([]string, []string) {
	for i, tok := range tokens {
		if tok == "in" {
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
