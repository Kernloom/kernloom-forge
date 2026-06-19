// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package conformance

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom-forge/internal/signing"
	"gopkg.in/yaml.v3"
)

type Fixtures struct {
	PublicKey             ed25519.PublicKey
	PrivateKey            ed25519.PrivateKey
	Valid                 contracts.RuntimeBundle
	UnsupportedSchema     contracts.RuntimeBundle
	UnsupportedCapability contracts.RuntimeBundle
	UnsupportedAction     contracts.RuntimeBundle
	UnsupportedMode       contracts.RuntimeBundle
	OfflineLKG            contracts.RuntimeBundle
}

func Generate(now time.Time) (Fixtures, error) {
	if now.IsZero() {
		now = time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC)
	}
	seed := []byte("kernloom-forge-conformance-seed!")
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	priv := ed25519.NewKeyFromSeed(seed)

	sign := func(name string, mutate func(*contracts.RuntimeBundle)) (contracts.RuntimeBundle, error) {
		b := baseBundle(name, now)
		if mutate != nil {
			mutate(&b)
		}
		return contracts.SignRuntimeBundle(b, "conformance-test", priv)
	}

	valid, err := sign("valid", nil)
	if err != nil {
		return Fixtures{}, err
	}
	unsupportedSchema, err := sign("unsupported-schema", func(b *contracts.RuntimeBundle) {
		b.APIVersion = "kernloom.io/runtime/v999"
	})
	if err != nil {
		return Fixtures{}, err
	}
	unsupportedCapability, err := sign("unsupported-capability", func(b *contracts.RuntimeBundle) {
		b.Spec.RuntimePolicyPack.Spec.CapabilitiesRequired = []string{"enforce.magic.teleport"}
		b.Spec.RuntimePolicyPack.Spec.Rules[0].Then.Capability = "enforce.magic.teleport"
	})
	if err != nil {
		return Fixtures{}, err
	}
	unsupportedAction, err := sign("unsupported-action", func(b *contracts.RuntimeBundle) {
		b.Spec.RuntimePolicyPack.Spec.Rules[0].Then.Level = "block"
		b.Spec.EnforcementBounds.AllowBlock = false
	})
	if err != nil {
		return Fixtures{}, err
	}
	unsupportedMode, err := sign("unsupported-mode", func(b *contracts.RuntimeBundle) {
		b.Spec.RuntimePDPProfile.Mode = "panic"
	})
	if err != nil {
		return Fixtures{}, err
	}
	offlineLKG, err := sign("offline-lkg", func(b *contracts.RuntimeBundle) {
		b.Spec.Failover.Behavior = "fail_static"
	})
	if err != nil {
		return Fixtures{}, err
	}
	return Fixtures{
		PublicKey:             pub,
		PrivateKey:            priv,
		Valid:                 valid,
		UnsupportedSchema:     unsupportedSchema,
		UnsupportedCapability: unsupportedCapability,
		UnsupportedAction:     unsupportedAction,
		UnsupportedMode:       unsupportedMode,
		OfflineLKG:            offlineLKG,
	}, nil
}

func Write(dir string, now time.Time) error {
	if dir == "" {
		return fmt.Errorf("conformance fixture output dir is required")
	}
	fixtures, err := Generate(now)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := signing.SavePrivateKey(filepath.Join(dir, "ed25519-private.pem"), fixtures.PrivateKey); err != nil {
		return err
	}
	if err := signing.SavePublicKey(filepath.Join(dir, "ed25519-public.pem"), fixtures.PublicKey); err != nil {
		return err
	}
	files := map[string]contracts.RuntimeBundle{
		"valid-runtime-bundle.yaml":                  fixtures.Valid,
		"unsupported-schema-runtime-bundle.yaml":     fixtures.UnsupportedSchema,
		"unsupported-capability-runtime-bundle.yaml": fixtures.UnsupportedCapability,
		"unsupported-action-runtime-bundle.yaml":     fixtures.UnsupportedAction,
		"unsupported-mode-runtime-bundle.yaml":       fixtures.UnsupportedMode,
		"offline-lkg-runtime-bundle.yaml":            fixtures.OfflineLKG,
	}
	for name, bundle := range files {
		raw, err := yaml.Marshal(bundle)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func baseBundle(name string, now time.Time) contracts.RuntimeBundle {
	return contracts.RuntimeBundle{
		TypeMeta: contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindRuntimeBundle},
		Metadata: contracts.ObjectMeta{
			Name:       name,
			NodeID:     "node-1",
			Generation: 1,
			IssuedAt:   now,
			ExpiresAt:  now.Add(24 * time.Hour),
		},
		Spec: contracts.RuntimeBundleSpec{
			RuntimePDPProfile: contracts.RuntimePDPProfile{Name: "conformance", Mode: "active"},
			RuntimePolicyPack: contracts.RuntimePolicyPack{
				TypeMeta: contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindRuntimePolicyPack},
				Metadata: contracts.ObjectMeta{
					Name:     name + "-pack",
					IssuedAt: now,
				},
				Spec: contracts.RuntimePolicyPackSpec{
					CapabilitiesRequired: []string{"enforce.traffic.rate_limit"},
					DefaultEffect:        "deny",
					Rules: []contracts.RuntimePolicyRule{{
						ID:   "risk-high-rate-limit",
						When: "risk.level in ['high', 'critical']",
						Then: contracts.RuntimeActionSpec{
							Capability: "enforce.traffic.rate_limit",
							Level:      "hard",
							TTL:        contracts.NewDuration(time.Minute),
						},
						ReasonCodes: []string{"risk_high"},
					}},
				},
			},
			EnforcementBounds: contracts.EnforcementBounds{AllowBlock: false},
			Failover:          contracts.FailoverConfig{Behavior: "fail_static"},
		},
	}
}
