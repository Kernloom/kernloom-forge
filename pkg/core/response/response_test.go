// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package response

import (
	"testing"
	"time"
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

func TestAlertRouteRuntimeRoute(t *testing.T) {
	route := AlertRoute{
		APIVersion: "kernloom.io/v1",
		Kind:       KindAlertRoute,
		Metadata:   Metadata{Name: "alert-route.security-ops"},
		Spec: AlertRouteSpec{
			Audience: Audience{Type: "group", Ref: "group.kernloom-security-ops"},
			Channels: []Channel{
				{Type: "slack", Ref: "channel.security-ops"},
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
