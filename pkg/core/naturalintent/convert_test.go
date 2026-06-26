// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package naturalintent

import (
	"strings"
	"testing"
)

func TestConvertQuotedProtectAllow(t *testing.T) {
	result, err := Convert([]byte(`
protect "ziti-controller"
allow group "kernloom-admins" to access "ziti-controller"
require "subject.risk.level" eq "low"
require "device.posture.status" eq "healthy"
default deny access to "ziti-controller"
when denied access to "ziti-controller" exceeds 5 within 15m then alert route "security-ops" severity "medium" dedupe 15m
never auto_block group "kernloom-admins"
`), Options{Owner: "security"})
	if err != nil {
		t.Fatal(err)
	}
	pol := result.Policy
	if pol.Metadata.Name != "protect-ziti-controller" {
		t.Fatalf("name = %q", pol.Metadata.Name)
	}
	if pol.Metadata.Environment != "" {
		t.Fatalf("environment = %q", pol.Metadata.Environment)
	}
	if pol.Spec.Subject.Type != "group" || pol.Spec.Subject.Ref != "kernloom-admins" {
		t.Fatalf("subject = %#v", pol.Spec.Subject)
	}
	if pol.Spec.Resource.Type != "endpoint" || pol.Spec.Resource.Ref != "ziti-controller" {
		t.Fatalf("resource = %#v", pol.Spec.Resource)
	}
	if len(pol.Spec.Conditions) != 2 {
		t.Fatalf("conditions = %#v", pol.Spec.Conditions)
	}
	if got := pol.Spec.Conditions[0].Type; got != "risk_level" {
		t.Fatalf("condition[0].type = %q", got)
	}
	if got := pol.Spec.Conditions[1].Type; got != "device_posture" {
		t.Fatalf("condition[1].type = %q", got)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("warnings = %#v", result.Warnings)
	}
	if got := result.Warnings[0]; !strings.Contains(got, `default deny`) {
		t.Fatalf("warning = %q", got)
	}
	if len(result.Notes) != 2 {
		t.Fatalf("notes = %#v", result.Notes)
	}
	if got := result.Notes[0]; !strings.Contains(got, `ResponsePolicy IR`) || !strings.Contains(got, `alert-route.security-ops`) {
		t.Fatalf("when note = %q", got)
	}
	if len(result.ResponseRules) != 1 {
		t.Fatalf("response rules = %#v", result.ResponseRules)
	}
	if len(result.DetectionRules) != 0 {
		t.Fatalf("detection rules should require EmitDetectionIR: %#v", result.DetectionRules)
	}
	if got := result.ResponseRules[0].Then[0].ID; got != "notify.alert.emit" {
		t.Fatalf("response action = %q", got)
	}
	if got := result.ResponseRules[0].Then[0].Route; got != "alert-route.security-ops" {
		t.Fatalf("response route = %q", got)
	}
	if len(result.Guardrails) != 1 {
		t.Fatalf("guardrails = %#v", result.Guardrails)
	}
	if got := result.Guardrails[0].ID; got != "never-auto-block-kernloom-admins" {
		t.Fatalf("guardrail id = %q", got)
	}
	if got := result.Guardrails[0].Subject.Ref; got != "kernloom-admins" {
		t.Fatalf("guardrail subject = %q", got)
	}
}

func TestConvertAutonomyLifecycle(t *testing.T) {
	result, err := Convert([]byte(`
intent "edge-autonomy"
protect service "public-edge"
allow all

autonomy "public-edge-runtime-autonomy":
  hold rate_limit source at 100 pps for 30s while enforcement feedback active
  step_down after clean 30s observe after 2m
  restore previous mitigation if pressure resumes during cooldown
  allow autonomous rate_limit for unknown sources
  allow autonomous temporary_block only after rate_limit was active
  require approval before identity disable
  never block more than 100 sources per tenant within 10m
  max autonomous block duration 15m
  require audit receipt for every enforcement
  max renewals 3
`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := result.AutonomyLifecycle
	if lifecycle == nil || len(lifecycle.Hold) != 1 {
		t.Fatalf("autonomy lifecycle = %#v", lifecycle)
	}
	hold := lifecycle.Hold[0]
	if hold.ID != "hold-rate-limit-while-enforcement-feedback-active" {
		t.Fatalf("hold id = %q", hold.ID)
	}
	if hold.Action.Capability != "enforce.traffic.rate_limit" || hold.Action.Level != "hard" {
		t.Fatalf("hold action = %#v", hold.Action)
	}
	if got := hold.Action.TTL.Duration.String(); got != "30s" {
		t.Fatalf("hold ttl = %s", got)
	}
	if got := hold.Action.Params["rate_pps"]; got != 100 {
		t.Fatalf("rate_pps = %#v", got)
	}
	if !hold.While.EnforcementFeedbackActive || len(hold.While.Levels) != 3 {
		t.Fatalf("hold condition = %#v", hold.While)
	}
	if got := lifecycle.StepDown.ObserveAfter.Duration.String(); got != "2m0s" {
		t.Fatalf("observe_after = %s", got)
	}
	if lifecycle.MaxRenewals != 3 {
		t.Fatalf("max renewals = %d", lifecycle.MaxRenewals)
	}
	if !lifecycle.RestorePreviousOnResume || !lifecycle.RequiresAudit {
		t.Fatalf("autonomy lifecycle flags = %#v", lifecycle)
	}
	if len(lifecycle.Allow) != 2 || lifecycle.Allow[0].Subject.Ref != "unknown" || lifecycle.Allow[1].RequiresPreviousAction != "enforce.traffic.rate_limit" {
		t.Fatalf("allowances = %#v", lifecycle.Allow)
	}
	if len(lifecycle.ApprovalRequired) != 1 || lifecycle.ApprovalRequired[0].Action != "enforce.identity.disable" {
		t.Fatalf("approval requirements = %#v", lifecycle.ApprovalRequired)
	}
	if len(lifecycle.BlastRadius) != 1 || lifecycle.BlastRadius[0].MaxTargets != 100 || lifecycle.BlastRadius[0].Window.Duration.String() != "10m0s" {
		t.Fatalf("blast radius = %#v", lifecycle.BlastRadius)
	}
	if len(lifecycle.MaxActionDuration) != 1 || lifecycle.MaxActionDuration[0].Duration.Duration.String() != "15m0s" {
		t.Fatalf("max duration = %#v", lifecycle.MaxActionDuration)
	}
	if !containsNaturalDiagnostic(result.Notes, "ENFORCED autonomy hold") {
		t.Fatalf("enforced hold note missing: %#v", result.Notes)
	}
	for _, want := range []string{
		"autonomy step_down is carried",
		"autonomy restore previous mitigation is carried",
		"autonomy blast-radius source-count windows are carried",
	} {
		if !containsNaturalDiagnostic(result.Warnings, want) {
			t.Fatalf("warning %q missing: %#v", want, result.Warnings)
		}
	}
}

func TestConvertCanSplitDetectionAndResponseIR(t *testing.T) {
	result, err := Convert([]byte(`
protect "ziti-controller"
when denied access to "ziti-controller" exceeds 5 within 15m then alert route "security-ops" severity "medium" dedupe 15m
`), Options{EmitDetectionIR: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.DetectionRules) != 1 {
		t.Fatalf("detection rules = %#v", result.DetectionRules)
	}
	if got := result.DetectionRules[0].ID; got != "denied-access-ziti-controller-exceeds-5-within-15m0s" {
		t.Fatalf("detection id = %q", got)
	}
	if len(result.ResponseRules) != 1 {
		t.Fatalf("response rules = %#v", result.ResponseRules)
	}
	if got := result.ResponseRules[0].When.Detection; got != result.DetectionRules[0].ID {
		t.Fatalf("response detection = %q", got)
	}
	if got := result.ResponseRules[0].When.Type; got != "" {
		t.Fatalf("response trigger type should move to detection, got %q", got)
	}
}

func TestConvertSignalWhenRulesToDetectionIR(t *testing.T) {
	result, err := Convert([]byte(`
protect application_group "admin-apps"
allow group "admins" to access application_group "admin-apps"
when risk equals medium then alert route "security-ops" severity "high" dedupe 15m
when "subject.risk.level" in ["high", "critical"] then deny source for 5m
`), Options{EmitDetectionIR: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.DetectionRules) != 2 {
		t.Fatalf("detection rules = %#v", result.DetectionRules)
	}
	first := result.DetectionRules[0]
	if got := first.Type; got != "metric.threshold" {
		t.Fatalf("detection type = %q", got)
	}
	if got := first.Params["key"]; got != "subject.risk.level" {
		t.Fatalf("detection key = %#v", got)
	}
	if got := first.Params["operator"]; got != "eq" {
		t.Fatalf("detection operator = %#v", got)
	}
	if got := first.Params["value"]; got != "medium" {
		t.Fatalf("detection value = %#v", got)
	}
	if len(result.ResponseRules) != 2 {
		t.Fatalf("response rules = %#v", result.ResponseRules)
	}
	if got := result.ResponseRules[0].When.Detection; got != first.ID {
		t.Fatalf("response detection = %q", got)
	}
	if got := result.ResponseRules[0].Then[0].ID; got != "notify.alert.emit" {
		t.Fatalf("alert action = %q", got)
	}
	if got := result.ResponseRules[1].Then[0].ID; got != "enforce.access.deny" {
		t.Fatalf("deny action = %q", got)
	}
	if got := result.ResponseRules[1].Then[0].Target.Scope; got != "source" {
		t.Fatalf("deny scope = %q", got)
	}
	if got := result.ResponseRules[1].Then[0].TTL.Duration.String(); got != "5m0s" {
		t.Fatalf("deny ttl = %q", got)
	}
}

func TestConvertRiskAtLeastToOrderedRiskSet(t *testing.T) {
	result, err := Convert([]byte(`
protect service "edge"
allow all
detection "runtime":
  detect "risk-high":
    when risk at least high
response "runtime":
  on "risk-high" then deny source for 5m
`), Options{EmitDetectionIR: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.DetectionRules) != 1 {
		t.Fatalf("detection rules = %#v", result.DetectionRules)
	}
	for _, rule := range result.DetectionRules {
		if got := rule.Params["key"]; got != "runtime.risk.level" {
			t.Fatalf("detection key = %#v", got)
		}
		if got := rule.Params["operator"]; got != "in" {
			t.Fatalf("detection operator = %#v", got)
		}
		values, ok := rule.Params["value"].([]string)
		if !ok || len(values) != 2 || values[0] != "high" || values[1] != "critical" {
			t.Fatalf("detection value = %#v", rule.Params["value"])
		}
	}

	inline, err := Convert([]byte(`
protect service "edge"
allow all
when risk at least high then deny source for 5m
`), Options{EmitDetectionIR: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(inline.DetectionRules) != 1 {
		t.Fatalf("inline detection rules = %#v", inline.DetectionRules)
	}
	if got := inline.DetectionRules[0].Params["key"]; got != "runtime.risk.level" {
		t.Fatalf("inline detection key = %#v", got)
	}
	values, ok := inline.DetectionRules[0].Params["value"].([]string)
	if !ok || len(values) != 2 || values[0] != "high" || values[1] != "critical" {
		t.Fatalf("inline detection value = %#v", inline.DetectionRules[0].Params["value"])
	}
}

func TestConvertAlertRouteFileChannel(t *testing.T) {
	result, err := Convert([]byte(`
intent "file-alert"
protect "ziti-controller"
allow all

detection "risk-detections":
  detect "risk-high":
    when risk at least high

response "risk-alerts":
  on "risk-high" then alert route "security-ops" severity "high" dedupe 5m

alert_route "security-ops":
  notify group "kernloom-security-ops"
  via ["file"]
`), Options{EmitDetectionIR: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.AlertRoutes) != 1 {
		t.Fatalf("alert routes = %#v", result.AlertRoutes)
	}
	if len(result.AlertRoutes[0].Channels) != 1 {
		t.Fatalf("channels = %#v", result.AlertRoutes[0].Channels)
	}
	if got := result.AlertRoutes[0].Channels[0].Type; got != "file" {
		t.Fatalf("channel type = %q", got)
	}
	if got := result.AlertRoutes[0].Channels[0].Ref; got != "file.security-ops" {
		t.Fatalf("channel ref = %q", got)
	}
}

func TestConvertSignalWhenPreservesEscalationParam(t *testing.T) {
	result, err := Convert([]byte(`
protect service "edge"
allow all
when risk equals medium then rate_limit source for 15m with escalation soft_to_hard
`), Options{EmitDetectionIR: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Policy.Spec.Subject.Type; got != "any" {
		t.Fatalf("subject type = %q", got)
	}
	if len(result.ResponseRules) != 1 {
		t.Fatalf("response rules = %#v", result.ResponseRules)
	}
	action := result.ResponseRules[0].Then[0]
	if got := action.ID; got != "enforce.traffic.rate_limit" {
		t.Fatalf("action id = %q", got)
	}
	if got := action.Target.Scope; got != "source" {
		t.Fatalf("target scope = %q", got)
	}
	if got := action.Params["escalation"]; got != "soft_to_hard" {
		t.Fatalf("escalation = %#v", got)
	}
	if !containsNaturalDiagnostic(result.Warnings, "response escalation \"soft_to_hard\" is carried") {
		t.Fatalf("escalation warning missing: %#v", result.Warnings)
	}
}

func TestConvertBlockBasedArchitectureIntent(t *testing.T) {
	result, err := Convert([]byte(`
intent "protect-ziti-controller-admin-access"

protect "ziti-controller" in "production" as "critical admin interface"

compose:
  access "ziti-controller-admin-access"
  requirements "low-risk-strong-auth"
  detection "ziti-controller-denied-access"
  response "ziti-controller-deny-escalation"
  alert_route "security-oncall"
  guardrail "never-autoblock-kernloom-admins"
  capabilities "ziti-controller-admin-protection"

access "ziti-controller-admin-access":
  default deny access to "ziti-controller"
  allow group "kernloom-admins" to access "ziti-controller"

requirements "low-risk-strong-auth":
  require "subject.risk.level" eq "low"
  require "session.authentication.strength" in ["mfa", "phishing_resistant_mfa"]

detection "ziti-controller-denied-access":
  detect "admin-deny":
    when denied access to "ziti-controller" by group "kernloom-admins" exceeds 3 within 15m

  detect "known-non-admin-deny":
    when denied access to "ziti-controller" by known subject excluding group "kernloom-admins" exceeds 5 within 15m

  detect "unknown-source-heavy-deny":
    when denied access to "ziti-controller" by unknown source exceeds 20 within 15m

  detect "sustained-pressure":
    when rate_limit drops to "ziti-controller" by unknown source sustained for 5m

response "ziti-controller-deny-escalation":
  on "admin-deny" then alert route "security-ops" severity "medium" dedupe 15m
  on "unknown-source-heavy-deny" then rate_limit source for 15m
  on "sustained-pressure" then temporary_block source for 10m
    require enforcement target excludes group "kernloom-admins"

alert_route "security-ops":
  notify group "kernloom-security-ops"
  via ["log", "email"]
  dedupe by ["tenant.id", "resource.id", "detection.id", "source.identity_or_ip"]
  create case false

guardrail "never-autoblock-kernloom-admins":
  never auto_block group "kernloom-admins"
  never quarantine group "kernloom-admins"
  never disable identity group "kernloom-admins"

capabilities "ziti-controller-admin-protection":
  require identity_based_access
  require context "subject.risk.level"
  require context "session.authentication.strength"
  require windowed_detection
  require traffic_rate_limit
  require temporary_traffic_block

gap_handling:
  fail on missing_context
  require_approval on identity_to_ip downgrade
`), Options{EmitDetectionIR: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Policy.Metadata.Name; got != "protect-ziti-controller-admin-access" {
		t.Fatalf("policy name = %q", got)
	}
	if got := result.Policy.Metadata.Environment; got != "production" {
		t.Fatalf("environment = %q", got)
	}
	if len(result.DetectionRules) != 4 {
		t.Fatalf("detections = %#v", result.DetectionRules)
	}
	knownNonAdmin := result.DetectionRules[1]
	if got := knownNonAdmin.Subject.Selector; got != "known_subject_excluding_group" {
		t.Fatalf("known-non-admin selector = %q", got)
	}
	if got := knownNonAdmin.Subject.Ref; got != "kernloom-admins" {
		t.Fatalf("known-non-admin ref = %q", got)
	}
	if got := result.DetectionRules[3].Type; got != "source.rate_limit_drops_sustained" {
		t.Fatalf("sustained detection type = %q", got)
	}
	if len(result.ResponseRules) != 3 {
		t.Fatalf("responses = %#v", result.ResponseRules)
	}
	blockAction := result.ResponseRules[2].Then[0]
	if got := blockAction.ID; got != "enforce.traffic.drop" {
		t.Fatalf("temporary_block action = %q", got)
	}
	if got := blockAction.Params["requires_target_excludes_group"]; got != "kernloom-admins" {
		t.Fatalf("blast-radius requirement = %#v", got)
	}
	blast, ok := blockAction.Params["blast_radius"].(map[string]any)
	if !ok || blast["unknown_behavior"] != "reject_hard_action" {
		t.Fatalf("structured blast-radius requirement = %#v", blockAction.Params["blast_radius"])
	}
	if len(result.Guardrails) != 3 {
		t.Fatalf("guardrails = %#v", result.Guardrails)
	}
	if len(result.AlertRoutes) != 1 {
		t.Fatalf("alert routes = %#v", result.AlertRoutes)
	}
	if got := result.AlertRoutes[0].Audience.Ref; got != "kernloom-security-ops" {
		t.Fatalf("route audience = %q", got)
	}
	if len(result.Capabilities) != 1 {
		t.Fatalf("capabilities = %#v", result.Capabilities)
	}
	if got := len(result.Capabilities[0].Spec.GapHandling); got != 2 {
		t.Fatalf("gap handling = %#v", result.Capabilities[0].Spec.GapHandling)
	}
}

func TestConvertResponsePreviousActionRequirement(t *testing.T) {
	result, err := Convert([]byte(`
protect "public-edge"

detection "edge-detections":
  detect "sustained-pressure":
    when rate_limit drops to "public-edge" by unknown source sustained for 5m

response "edge-responses":
  on "sustained-pressure" then temporary_block source for 10m
    require previous action "enforce.traffic.rate_limit" active
    require risk confidence at least high
    require risk signal fresher than 2m
    require at least 2 independent signals before block
    allow local enforcement state evidence
    require enforcement target excludes group "kernloom-admins"
`), Options{EmitDetectionIR: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ResponseRules) != 1 {
		t.Fatalf("responses = %#v", result.ResponseRules)
	}
	params := result.ResponseRules[0].Then[0].Params
	if got := params["previous_action_id"]; got != "enforce.traffic.rate_limit" {
		t.Fatalf("previous action id = %#v", got)
	}
	if got := params["previous_action_active"]; got != true {
		t.Fatalf("previous action active = %#v", got)
	}
	evidence, ok := params["previous_action_evidence"].([]string)
	if !ok {
		t.Fatalf("previous action evidence = %#v", params["previous_action_evidence"])
	}
	if len(evidence) != 2 || evidence[0] != "runtime_response_state" || evidence[1] != "local_runtime_state" {
		t.Fatalf("previous action evidence = %#v", evidence)
	}
	if got := params["allow_local_runtime_state_evidence"]; got != true {
		t.Fatalf("local state evidence flag = %#v", got)
	}
	if got := params["min_risk_confidence"]; got != 0.8 {
		t.Fatalf("min risk confidence = %#v", got)
	}
	if got := params["max_risk_age_seconds"]; got != 120 {
		t.Fatalf("max risk age seconds = %#v", got)
	}
	if got := params["min_independent_signals"]; got != 2 {
		t.Fatalf("min independent signals = %#v", got)
	}
	if containsNaturalDiagnostic(result.Warnings, "independent-signal provenance is approximated") {
		t.Fatalf("independent signal warning should not be emitted anymore: %#v", result.Warnings)
	}
}

func TestConvertResponseRateLimitWithRatePPS(t *testing.T) {
	result, err := Convert([]byte(`
protect service "public-edge"

response "edge-responses":
  on "risk-elevated" then rate_limit source at 100 pps for 1m
`), Options{EmitDetectionIR: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ResponseRules) != 1 {
		t.Fatalf("responses = %#v", result.ResponseRules)
	}
	action := result.ResponseRules[0].Then[0]
	if action.ID != "enforce.traffic.rate_limit" || action.Target.Scope != "source" {
		t.Fatalf("action = %#v", action)
	}
	if got := action.Params["rate_pps"]; got != 100 {
		t.Fatalf("rate_pps = %#v", got)
	}
	if got := action.TTL.Duration.String(); got != "1m0s" {
		t.Fatalf("ttl = %s", got)
	}
}

func containsNaturalDiagnostic(values []string, needle string) bool {
	for _, value := range values {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func TestConvertRejectsUnknownContextKey(t *testing.T) {
	_, err := Convert([]byte(`
protect service "admin-api"
allow group "admins" to access service "admin-api"
require "subject.risk.mood" eq "spicy"
`), Options{})
	if err == nil {
		t.Fatal("expected unknown context key to fail")
	}
	if !strings.Contains(err.Error(), `unknown context key "subject.risk.mood"`) {
		t.Fatalf("error = %v", err)
	}
}

func TestConvertDeduplicatesDetectionIR(t *testing.T) {
	result, err := Convert([]byte(`
protect "ziti-controller"
when denied access to "ziti-controller" exceeds 5 within 15m then alert route "security-ops" severity "medium" dedupe 15m
when denied access to "ziti-controller" exceeds 5 within 15m then rate_limit for 5m
`), Options{EmitDetectionIR: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.DetectionRules) != 1 {
		t.Fatalf("detection rules = %#v", result.DetectionRules)
	}
	if len(result.ResponseRules) != 2 {
		t.Fatalf("response rules = %#v", result.ResponseRules)
	}
	for _, rule := range result.ResponseRules {
		if got := rule.When.Detection; got != result.DetectionRules[0].ID {
			t.Fatalf("response detection = %q", got)
		}
	}
}

func TestConvertTypedDetectionResourceUsesResourceRef(t *testing.T) {
	result, err := Convert([]byte(`
protect api "public-api"
detection "public-api-detections":
  detect "unknown-source-deny":
    when denied access to api "public-api" by unknown source exceeds 5 within 15m
  detect "sustained-pressure":
    when rate_limit drops to api "public-api" by unknown source sustained for 5m
`), Options{EmitDetectionIR: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.DetectionRules) != 2 {
		t.Fatalf("detections = %#v", result.DetectionRules)
	}
	for _, rule := range result.DetectionRules {
		if got := rule.ResourceRef; got != "public-api" {
			t.Fatalf("resourceRef for %s = %q", rule.ID, got)
		}
		if got := rule.Params["group_by"]; got == nil {
			t.Fatalf("group_by missing for %s: %#v", rule.ID, rule.Params)
		}
	}
}

func TestConvertTypedSelectors(t *testing.T) {
	result, err := Convert([]byte(`
protect service "payments-api"
allow user "alice@example.com" to access service "payments-api"
`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Policy.Spec.Subject.Type; got != "user" {
		t.Fatalf("subject type = %q", got)
	}
	if got := result.Policy.Spec.Resource.Type; got != "service" {
		t.Fatalf("resource type = %q", got)
	}
}

func TestConvertRequireAliasesAndListValues(t *testing.T) {
	result, err := Convert([]byte(`
protect service "admin-api"
allow group "admins" to access service "admin-api"
require subject risk eq "low"
require session authentication in ["mfa", "phishing_resistant_mfa"]
`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	conditions := result.Policy.Spec.Conditions
	if len(conditions) != 2 {
		t.Fatalf("conditions = %#v", conditions)
	}
	if got := conditions[0].Signal; got != "subject.risk.level" {
		t.Fatalf("condition[0].signal = %q", got)
	}
	if got := conditions[0].ID; got != "require-subject-risk-level" {
		t.Fatalf("condition[0].id = %q", got)
	}
	if got := conditions[1].Signal; got != "session.authentication.strength" {
		t.Fatalf("condition[1].signal = %q", got)
	}
	values, ok := conditions[1].Value.([]string)
	if !ok {
		t.Fatalf("condition[1].value type = %T", conditions[1].Value)
	}
	if len(values) != 2 || values[0] != "mfa" || values[1] != "phishing_resistant_mfa" {
		t.Fatalf("condition[1].value = %#v", values)
	}
}

func TestConvertResponseActionAliases(t *testing.T) {
	result, err := Convert([]byte(`
protect service "admin-api"
when denied access to "admin-api" exceeds 10 within 5m then quarantine for 15m
`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("warnings = %#v", result.Warnings)
	}
	if len(result.Notes) != 1 {
		t.Fatalf("notes = %#v", result.Notes)
	}
	if got := result.Notes[0]; !strings.Contains(got, `ResponsePolicy IR`) {
		t.Fatalf("note = %q", got)
	}
	if len(result.ResponseRules) != 1 {
		t.Fatalf("response rules = %#v", result.ResponseRules)
	}
	if got := result.ResponseRules[0].Then[0].ID; got != "enforce.network.quarantine" {
		t.Fatalf("response action = %q", got)
	}
	if got := result.ResponseRules[0].Then[0].TTL.Duration.String(); got != "15m0s" {
		t.Fatalf("response ttl = %q", got)
	}
}

func TestConvertRejectsUnroutedAlert(t *testing.T) {
	_, err := Convert([]byte(`
protect service "admin-api"
when denied access to "admin-api" exceeds 10 within 5m then alert for 15m
`), Options{})
	if err == nil {
		t.Fatal("expected unrouted alert to fail")
	}
	if !strings.Contains(err.Error(), "alert action must use") {
		t.Fatalf("error = %v", err)
	}
}
