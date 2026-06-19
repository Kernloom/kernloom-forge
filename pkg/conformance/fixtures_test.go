// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package conformance_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom-forge/pkg/conformance"
)

func TestGenerateFixtures(t *testing.T) {
	now := fixedNow()
	f, err := conformance.Generate(now)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := contracts.VerifyRuntimeBundle(f.Valid, f.PublicKey, now); err != nil {
		t.Fatalf("valid fixture verify: %v", err)
	}
	if err := contracts.VerifyRuntimeBundle(f.UnsupportedCapability, f.PublicKey, now); err != nil {
		t.Fatalf("unsupported-capability fixture should still be signed: %v", err)
	}
	if err := contracts.VerifyRuntimeBundle(f.UnsupportedSchema, f.PublicKey, now); err == nil {
		t.Fatal("unsupported schema fixture should fail schema validation")
	}
}

func TestWriteFixtures(t *testing.T) {
	dir := t.TempDir()
	if err := conformance.Write(dir, fixedNow()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for _, name := range []string{
		"ed25519-public.pem",
		"valid-runtime-bundle.yaml",
		"unsupported-schema-runtime-bundle.yaml",
		"unsupported-capability-runtime-bundle.yaml",
		"unsupported-action-runtime-bundle.yaml",
		"unsupported-mode-runtime-bundle.yaml",
		"offline-lkg-runtime-bundle.yaml",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("missing fixture %s: %v", name, err)
		}
	}
}

func fixedNow() time.Time {
	return time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC)
}
