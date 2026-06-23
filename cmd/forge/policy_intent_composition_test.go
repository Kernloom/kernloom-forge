// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPolicyCompositionFromIntentValidatesDigest(t *testing.T) {
	dir := t.TempDir()
	access := []byte(`apiVersion: kernloom.io/v1
kind: AccessPolicy
metadata:
  name: protect-api
  version: 1.0.0
spec:
  subject:
    type: group
    ref: admins
  action: access
  resource:
    type: endpoint
    ref: api
  effect: allow
`)
	accessPath := filepath.Join(dir, "access.yaml")
	if err := os.WriteFile(accessPath, access, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(access)
	intentPath := filepath.Join(dir, "intent.yaml")
	if err := os.WriteFile(intentPath, []byte(`apiVersion: kernloom.io/v1
kind: PolicyIntent
metadata:
  name: protect-api-intent
spec:
  documents:
    access:
      - kind: AccessPolicy
        name: protect-api
        version: 1.0.0
        ref: access.yaml
        digest: sha256:`+hex.EncodeToString(sum[:])+`
`), 0o644); err != nil {
		t.Fatal(err)
	}
	comp, err := loadPolicyCompositionFromIntent(intentPath, "")
	if err != nil {
		t.Fatalf("loadPolicyCompositionFromIntent: %v", err)
	}
	if comp.AccessPolicy.Metadata.Name != "protect-api" {
		t.Fatalf("access policy = %q", comp.AccessPolicy.Metadata.Name)
	}
}

func TestLoadPolicyCompositionFromIntentRejectsDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "access.yaml"), []byte(`apiVersion: kernloom.io/v1
kind: AccessPolicy
metadata:
  name: protect-api
spec:
  subject:
    type: group
    ref: admins
  action: access
  resource:
    type: endpoint
    ref: api
  effect: allow
`), 0o644); err != nil {
		t.Fatal(err)
	}
	intentPath := filepath.Join(dir, "intent.yaml")
	if err := os.WriteFile(intentPath, []byte(`apiVersion: kernloom.io/v1
kind: PolicyIntent
metadata:
  name: protect-api-intent
spec:
  documents:
    access:
      - kind: AccessPolicy
        ref: access.yaml
        digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadPolicyCompositionFromIntent(intentPath, "")
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
}

func TestLoadPolicyCompositionFromIntentAllowsMultipleAccessPolicies(t *testing.T) {
	dir := t.TempDir()
	writeAccess := func(name, resource string) string {
		raw := []byte(`apiVersion: kernloom.io/v1
kind: AccessPolicy
metadata:
  name: ` + name + `
spec:
  subject:
    type: any
  action: access
  resource:
    type: endpoint
    ref: ` + resource + `
  effect: allow
`)
		path := filepath.Join(dir, name+".yaml")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		return "sha256:" + digestHex(raw)
	}
	digestA := writeAccess("protect-api", "api")
	digestB := writeAccess("protect-console", "console")
	intentPath := filepath.Join(dir, "intent.yaml")
	if err := os.WriteFile(intentPath, []byte(`apiVersion: kernloom.io/v1
kind: PolicyIntent
metadata:
  name: multi-access-intent
spec:
  documents:
    access:
      - kind: AccessPolicy
        name: protect-api
        ref: protect-api.yaml
        digest: `+digestA+`
      - kind: AccessPolicy
        name: protect-console
        ref: protect-console.yaml
        digest: `+digestB+`
`), 0o644); err != nil {
		t.Fatal(err)
	}
	comp, err := loadPolicyCompositionFromIntent(intentPath, "")
	if err != nil {
		t.Fatalf("loadPolicyCompositionFromIntent: %v", err)
	}
	if len(comp.AccessPolicies) != 2 {
		t.Fatalf("access policies = %d", len(comp.AccessPolicies))
	}
	if comp.SourceName() != "multi-access-intent" {
		t.Fatalf("source name = %q", comp.SourceName())
	}
}

func TestCompilePolicyIntentMergesMultipleAccessPolicies(t *testing.T) {
	dir := t.TempDir()
	writeAccess := func(name, resource string) string {
		raw := []byte(`apiVersion: kernloom.io/v1
kind: AccessPolicy
metadata:
  name: ` + name + `
spec:
  subject:
    type: any
  action: access
  resource:
    type: endpoint
    ref: ` + resource + `
  effect: allow
`)
		path := filepath.Join(dir, name+".yaml")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		return "sha256:" + digestHex(raw)
	}
	digestA := writeAccess("protect-api", "api")
	digestB := writeAccess("protect-console", "console")
	intentPath := filepath.Join(dir, "intent.yaml")
	if err := os.WriteFile(intentPath, []byte(`apiVersion: kernloom.io/v1
kind: PolicyIntent
metadata:
  name: multi-access-intent
spec:
  documents:
    access:
      - kind: AccessPolicy
        name: protect-api
        ref: protect-api.yaml
        digest: `+digestA+`
      - kind: AccessPolicy
        name: protect-console
        ref: protect-console.yaml
        digest: `+digestB+`
`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, plans, _, err := compilePlansFromInput("", intentPath, "", filepath.Join("..", "..", "examples", "adapters"), filepath.Join("..", "..", "examples", "profiles"), nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("compilePlansFromInput: %v", err)
	}
	if len(plans) == 0 {
		t.Fatal("no plans")
	}
	for _, p := range plans {
		if p.Metadata.SourcePolicy != "multi-access-intent" {
			t.Fatalf("source policy = %q", p.Metadata.SourcePolicy)
		}
		foundA, foundB := false, false
		for _, req := range p.Spec.Requirements {
			if strings.HasPrefix(req.ID, "protect-api.") {
				foundA = true
			}
			if strings.HasPrefix(req.ID, "protect-console.") {
				foundB = true
			}
		}
		if !foundA || !foundB {
			t.Fatalf("merged plan %s missing prefixed requirements: a=%v b=%v reqs=%#v", p.Metadata.Target, foundA, foundB, p.Spec.Requirements)
		}
	}
}

func digestHex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
