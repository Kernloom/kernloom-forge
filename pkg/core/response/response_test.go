// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package response

import (
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
)

func TestResponsePolicyRuntimeRules(t *testing.T) {
	p := Policy{
		APIVersion: "kernloom.io/v1",
		Kind:       KindResponsePolicy,
		Metadata:   Metadata{Name: "ziti-response"},
		Spec: Spec{Rules: []Rule{{
			ID: "alert-on-deny",
			When: Trigger{
				Type:        "access.denied_threshold",
				ResourceRef: "ziti-controller",
				Threshold:   5,
				Window:      "15m",
			},
			Then: ActionHolder{Action: Action{
				ID:       "notify.alert.emit",
				Route:    "alert-route.security-ops",
				Severity: "medium",
				Dedupe:   "15m",
			}},
		}}},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rules, err := p.RuntimeResponseRules()
	if err != nil {
		t.Fatalf("runtime rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d", len(rules))
	}
	if got := rules[0].Then[0].Route; got != "alert-route.security-ops" {
		t.Fatalf("route = %q", got)
	}
	if got := rules[0].When.Window.Duration; got != 15*time.Minute {
		t.Fatalf("window = %s", got)
	}
}

func TestDetectionPolicyRuntimeRules(t *testing.T) {
	p := DetectionPolicy{
		APIVersion: "kernloom.io/v1",
		Kind:       KindDetectionPolicy,
		Metadata:   Metadata{Name: "ziti-detections"},
		Spec: DetectionSpec{Rules: []DetectionRule{{
			ID: "admin-deny",
			When: DetectionWhen{
				Type:        "access.denied_threshold",
				ResourceRef: "ziti-controller",
				Subject: DetectionSubject{
					Type: "group",
					Ref:  "kernloom-admins",
				},
				Threshold: 3,
				Window:    "15m",
				Scope:     "source",
			},
		}}},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rules, err := p.RuntimeDetectionRules()
	if err != nil {
		t.Fatalf("runtime rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d", len(rules))
	}
	if got := rules[0].Subject.Ref; got != "kernloom-admins" {
		t.Fatalf("subject ref = %q", got)
	}
	if got := rules[0].Window.Duration; got != 15*time.Minute {
		t.Fatalf("window = %s", got)
	}
	if got := rules[0].Params["evaluator_type"]; got != "windowed" {
		t.Fatalf("evaluator_type = %#v", got)
	}
	if got := rules[0].Params["missing_context"]; got != "not_match" {
		t.Fatalf("missing_context = %#v", got)
	}
	groupBy, ok := rules[0].Params["group_by"].([]string)
	if !ok || len(groupBy) != 1 || groupBy[0] != "source.identity_or_ip" {
		t.Fatalf("group_by = %#v", rules[0].Params["group_by"])
	}
}

func TestDetectionPolicyRejectsStatelessWindow(t *testing.T) {
	p := DetectionPolicy{
		APIVersion: "kernloom.io/v1",
		Kind:       KindDetectionPolicy,
		Metadata:   Metadata{Name: "bad-detections"},
		Spec: DetectionSpec{
			Evaluator: DetectionEvaluatorSpec{Type: "stateless"},
			Rules: []DetectionRule{{
				ID: "windowed",
				When: DetectionWhen{
					Type:   "access.denied_threshold",
					Window: "15m",
				},
			}},
		},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected stateless evaluator with window to fail")
	}
}

func TestAlertRouteRuntimeRoute(t *testing.T) {
	route := AlertRoute{
		APIVersion: "kernloom.io/v1",
		Kind:       KindAlertRoute,
		Metadata:   Metadata{Name: "alert-route.security-ops"},
		Spec: AlertRouteSpec{
			Audience: Audience{Type: "group", Ref: "group.kernloom-security-ops"},
			Channels: []Channel{
				{Type: "log", Ref: "log.security-ops"},
				{Type: "email", Ref: "mailinglist.security-ops"},
			},
			DefaultSeverity: "medium",
			Deduplication: Deduplication{
				Enabled: true,
				Window:  "15m",
				Keys:    []string{"resource.id", "detection.id", "source.identity_or_ip"},
			},
		},
	}
	if err := route.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	runtimeRoute, err := route.RuntimeAlertRoute()
	if err != nil {
		t.Fatalf("runtime route: %v", err)
	}
	if runtimeRoute.ID != "alert-route.security-ops" {
		t.Fatalf("id = %q", runtimeRoute.ID)
	}
	if len(runtimeRoute.Channels) != 2 {
		t.Fatalf("channels = %#v", runtimeRoute.Channels)
	}
	if got := runtimeRoute.Deduplication.Window.Duration; got != 15*time.Minute {
		t.Fatalf("dedupe window = %s", got)
	}
}

func TestValidateRuntimeReferencesRequiresKnownDetectionAndRoute(t *testing.T) {
	detections := []contracts.RuntimeDetectionRule{{
		ID:   "admin-deny",
		Type: "access.denied_threshold",
	}}
	routes := []contracts.RuntimeAlertRoute{{
		ID:              "alert-route.security-ops",
		DefaultSeverity: "medium",
		Deduplication: contracts.RuntimeAlertDeduplication{
			Enabled: true,
			Window:  contracts.NewDuration(15 * time.Minute),
		},
	}}
	snapshot := contracts.RegistrySnapshot{
		ActionContracts: []contracts.RuntimeActionContractEntry{{
			ID: "notify.alert.emit",
		}},
		Capabilities: []contracts.CapabilityEntry{{
			ID: "notify.alert.emit",
		}},
	}

	good := []contracts.RuntimeResponseRule{{
		ID: "alert-admin-deny",
		When: contracts.RuntimeResponseTrigger{
			Detection: "admin-deny",
		},
		Then: []contracts.RuntimeResponseAction{{
			ID:       "notify.alert.emit",
			Route:    "alert-route.security-ops",
			Severity: "medium",
			Dedupe:   contracts.NewDuration(15 * time.Minute),
		}},
	}}
	if err := ValidateRuntimeReferences(detections, good, routes, snapshot); err != nil {
		t.Fatalf("good references should validate: %v", err)
	}

	badDetection := append([]contracts.RuntimeResponseRule(nil), good...)
	badDetection[0].When.Detection = "missing"
	if err := ValidateRuntimeReferences(detections, badDetection, routes, snapshot); err == nil {
		t.Fatal("expected unknown detection to fail")
	}

	badRoute := append([]contracts.RuntimeResponseRule(nil), good...)
	badRoute[0].Then[0].Route = "missing-route"
	if err := ValidateRuntimeReferences(detections, badRoute, routes, snapshot); err == nil {
		t.Fatal("expected unknown route to fail")
	}
}
