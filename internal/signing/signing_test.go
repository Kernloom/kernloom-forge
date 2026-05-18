// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package signing_test

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/kernloom/kernloom-forge/internal/signing"
)

func TestGenerateKeyPair(t *testing.T) {
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key size: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key size: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
}

func TestSaveLoadPrivateKey(t *testing.T) {
	_, priv, _ := signing.GenerateKeyPair()
	path := filepath.Join(t.TempDir(), "test.key")

	if err := signing.SavePrivateKey(path, priv); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}

	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("private key file mode: got %o, want 0600", fi.Mode().Perm())
	}

	loaded, err := signing.LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if string(loaded) != string(priv) {
		t.Error("loaded private key does not match original")
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, _ := signing.GenerateKeyPair()
	content := []byte("apiVersion: kernloom.io/v1alpha1\nkind: LocalPolicyPack\n")

	signed, err := signing.SignPackYAML(content, priv)
	if err != nil {
		t.Fatalf("SignPackYAML: %v", err)
	}

	// Signed content must be longer than original.
	if len(signed) <= len(content) {
		t.Error("signed output should be longer than original")
	}

	// Verification must pass with correct key.
	if err := signing.VerifyPackYAML(signed, pub); err != nil {
		t.Errorf("VerifyPackYAML: %v", err)
	}

	// Verification must fail with wrong key.
	otherPub, _, _ := signing.GenerateKeyPair()
	if err := signing.VerifyPackYAML(signed, otherPub); err == nil {
		t.Error("verification with wrong key should fail")
	}
}

func TestVerify_Unsigned_Fails(t *testing.T) {
	pub, _, _ := signing.GenerateKeyPair()
	unsigned := []byte("apiVersion: kernloom.io/v1alpha1\nkind: LocalPolicyPack\n")
	if err := signing.VerifyPackYAML(unsigned, pub); err == nil {
		t.Error("unsigned pack should fail verification")
	}
}

func TestVerify_TamperedContent_Fails(t *testing.T) {
	pub, priv, _ := signing.GenerateKeyPair()
	content := []byte("name: original\n")
	signed, _ := signing.SignPackYAML(content, priv)

	// Tamper with the content (flip a byte).
	tampered := make([]byte, len(signed))
	copy(tampered, signed)
	tampered[0] ^= 0xFF

	if err := signing.VerifyPackYAML(tampered, pub); err == nil {
		t.Error("tampered content should fail verification")
	}
}

func TestSignPackYAML_ContentUnchanged(t *testing.T) {
	_, priv, _ := signing.GenerateKeyPair()
	content := []byte("spec:\n  rules: []\n")
	signed, _ := signing.SignPackYAML(content, priv)

	// The original content must appear verbatim at the start of the signed output.
	if string(signed[:len(content)]) != string(content) {
		t.Error("original content must be preserved at start of signed output")
	}
}
