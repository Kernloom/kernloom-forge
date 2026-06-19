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
when denied access to "ziti-controller" exceeds 5 within 15m then alert
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
	if len(result.Warnings) != 3 {
		t.Fatalf("warnings = %#v", result.Warnings)
	}
	if got := result.Warnings[1]; !strings.Contains(got, `exceeding 5 within 15m then alert (observe.signal.emit)`) {
		t.Fatalf("when warning = %q", got)
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
	if len(result.Warnings) != 1 {
		t.Fatalf("warnings = %#v", result.Warnings)
	}
	if got := result.Warnings[0]; !strings.Contains(got, `then quarantine (enforce.network.quarantine)`) {
		t.Fatalf("warning = %q", got)
	}
}
