// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package guardrail

import "testing"

func TestFromNeverTokensAutoBlockGroup(t *testing.T) {
	g, err := FromNeverTokens([]string{"auto_block", "group", "kernloom-admins"})
	if err != nil {
		t.Fatal(err)
	}
	if g.ID != "never-auto-block-kernloom-admins" {
		t.Fatalf("id = %q", g.ID)
	}
	if g.Subject.Type != "group" || g.Subject.Ref != "kernloom-admins" {
		t.Fatalf("subject = %#v", g.Subject)
	}
	if len(g.ForbiddenActions) != 4 {
		t.Fatalf("forbidden actions = %#v", g.ForbiddenActions)
	}
	if g.Enforcement.UnknownBehavior != "reject_hard_action" {
		t.Fatalf("unknown behavior = %q", g.Enforcement.UnknownBehavior)
	}
}

func TestPolicyRuntimeGuardrails(t *testing.T) {
	p := &Policy{
		APIVersion: "kernloom.io/v1",
		Kind:       KindGuardrailPolicy,
		Metadata:   Metadata{Name: "admin-safety"},
		Spec: Spec{Invariants: []Invariant{{
			ID:      "never-auto-block-admins",
			Type:    "never",
			Subject: Subject{Type: "group", Ref: "kernloom-admins"},
			ForbiddenActions: []string{
				"auto_block",
			},
		}}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	guardrails, err := p.RuntimeGuardrails()
	if err != nil {
		t.Fatal(err)
	}
	if len(guardrails) != 1 {
		t.Fatalf("guardrails = %d", len(guardrails))
	}
	if guardrails[0].Enforcement.ViolationBehavior != "reject_action" {
		t.Fatalf("violation behavior = %q", guardrails[0].Enforcement.ViolationBehavior)
	}
}
