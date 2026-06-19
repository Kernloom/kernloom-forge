// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package enrollment_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kernloom/kernloom-forge/internal/enrollment"
)

func TestStoreCreateAndConsume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.yaml")
	store, err := enrollment.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, rec, err := store.Create("node-1", time.Hour, "manual test")
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" {
		t.Fatal("raw token should be returned once")
	}
	if rec.TokenHash == "" || rec.TokenHash == raw {
		t.Fatal("store record should contain a hash, not the raw token")
	}

	reloaded, err := enrollment.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Consume("node-1", raw); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := reloaded.Consume("node-1", raw); err == nil {
		t.Fatal("second consume should fail")
	}
}

func TestStoreConsumeRejectsWrongNode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.yaml")
	store, err := enrollment.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := store.Create("node-1", time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Consume("node-2", raw); err == nil {
		t.Fatal("consume for wrong node should fail")
	}
}
