// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package context_test

import (
	"testing"

	ctx "github.com/kernloom/kernloom-forge/pkg/core/context"
)

const canonicalRegistryYAML = `
apiVersion: kernloom.io/v1alpha1
kind: ContextKeyRegistry
metadata:
  name: test-registry
  version: "1.0"
spec:
  keys:
    - id: device.posture.status
      type: string_enum
      values: [healthy, degraded, unhealthy, unknown]
      scope: device
      defaultTTL: 15m
      permittedSources: [edr, mdm, kernloom_risk_engine]

    - id: subject.role
      type: string
      scope: subject
      defaultTTL: 8h
      permittedSources: [identity_provider]

    - id: session.authentication.strength
      type: string_enum
      values: [none, password, mfa, phishing_resistant_mfa]
      scope: session
      defaultTTL: 8h
`

func TestRegistry_Has(t *testing.T) {
	reg, err := ctx.ParseRegistry([]byte(canonicalRegistryYAML))
	if err != nil {
		t.Fatalf("ParseRegistry: %v", err)
	}
	if !reg.Has("device.posture.status") {
		t.Error("expected device.posture.status to be registered")
	}
	if reg.Has("openziti.posture_result") {
		t.Error("vendor-namespaced key should not be in canonical registry")
	}
	if reg.Has("nonexistent.key") {
		t.Error("unknown key should return false")
	}
}

func TestRegistry_ValidateValue_Enum(t *testing.T) {
	reg, err := ctx.ParseRegistry([]byte(canonicalRegistryYAML))
	if err != nil {
		t.Fatalf("ParseRegistry: %v", err)
	}

	if err := reg.ValidateValue("device.posture.status", "healthy"); err != nil {
		t.Errorf("'healthy' should be valid: %v", err)
	}
	if err := reg.ValidateValue("device.posture.status", "pass"); err == nil {
		t.Error("'pass' should be invalid for device.posture.status (OpenZiti value, not canonical)")
	}
	if err := reg.ValidateValue("device.posture.status", "compliant"); err == nil {
		t.Error("'compliant' should be invalid for device.posture.status (MDM value, not canonical)")
	}
}

func TestRegistry_ValidateValue_FreeString(t *testing.T) {
	reg, err := ctx.ParseRegistry([]byte(canonicalRegistryYAML))
	if err != nil {
		t.Fatalf("ParseRegistry: %v", err)
	}
	// Free string types accept any value.
	if err := reg.ValidateValue("subject.role", "investors"); err != nil {
		t.Errorf("free string should accept any value: %v", err)
	}
}

func TestRegistry_ValidateValue_UnknownKey(t *testing.T) {
	reg, err := ctx.ParseRegistry([]byte(canonicalRegistryYAML))
	if err != nil {
		t.Fatalf("ParseRegistry: %v", err)
	}
	if err := reg.ValidateValue("openziti.posture_result", "pass"); err == nil {
		t.Error("unknown key should return error")
	}
}

func TestRegistry_ValidateSource(t *testing.T) {
	reg, err := ctx.ParseRegistry([]byte(canonicalRegistryYAML))
	if err != nil {
		t.Fatalf("ParseRegistry: %v", err)
	}
	if err := reg.ValidateSource("device.posture.status", "edr"); err != nil {
		t.Errorf("edr should be a permitted source: %v", err)
	}
	if err := reg.ValidateSource("device.posture.status", "openziti-pip"); err == nil {
		t.Error("openziti-pip should not be permitted to supply device.posture.status directly")
	}
	// subject.role permits identity_provider.
	if err := reg.ValidateSource("subject.role", "identity_provider"); err != nil {
		t.Errorf("identity_provider should be permitted: %v", err)
	}
}

func TestRegistry_ValidateSignal(t *testing.T) {
	reg, err := ctx.ParseRegistry([]byte(canonicalRegistryYAML))
	if err != nil {
		t.Fatalf("ParseRegistry: %v", err)
	}

	// Known signal → OK.
	r := reg.ValidateSignal("device.posture.status")
	if !r.OK {
		t.Errorf("known signal should be OK, got: %s", r.Message)
	}

	// Unknown vendor-namespaced signal → not OK, with suggestions.
	r = reg.ValidateSignal("subject.unknown_field")
	if r.OK {
		t.Error("unknown field should not be OK")
	}
	if r.Message == "" {
		t.Error("validation message should not be empty for unknown key")
	}
	// Should suggest keys with "subject." prefix.
	if len(r.Suggestions) == 0 {
		t.Error("expected suggestions for unknown subject.* key")
	}
}

func TestRegistry_DuplicateKey(t *testing.T) {
	dupYAML := `
apiVersion: kernloom.io/v1alpha1
kind: ContextKeyRegistry
metadata:
  name: dup-test
  version: "1.0"
spec:
  keys:
    - id: device.posture.status
      type: string_enum
      values: [healthy, unhealthy]
      scope: device
    - id: device.posture.status
      type: string
      scope: device
`
	_, err := ctx.ParseRegistry([]byte(dupYAML))
	if err == nil {
		t.Error("duplicate key should return error")
	}
}

func TestRiskModel_VendorKeyRejected(t *testing.T) {
	riskyYAML := `
apiVersion: kernloom.io/risk/v1alpha1
kind: RiskModel
metadata:
  name: bad-model
  version: "1.0.0"
spec:
  scopeTypes: [subject]
  inputs:
    - id: bad_rule
      source: context
      key: openziti.posture_result
      match: fail
      baseContribution: 40
  output:
    range: {min: 0, max: 100}
    levels:
      low: [0, 29]
  validity:
    ttl: 30m
`
	// This import requires the risk package.
	_ = riskyYAML
	// Tested via risk package — see risk_model_test.go
}
