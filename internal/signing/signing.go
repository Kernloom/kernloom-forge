// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package signing provides Ed25519 key generation, pack signing, and
// verification for Kernloom LocalPolicyPacks.
//
// Signing scheme:
//  1. Forge renders the pack to YAML (without a signature field).
//  2. The YAML bytes are signed with an Ed25519 private key.
//  3. "signature: <base64>" is appended as the last line of the file.
//
// Verification in KLIQ:
//  1. KLIQ reads the raw file bytes.
//  2. Splits at the last "\nsignature: " occurrence.
//  3. Verifies ed25519.Verify(pubKey, contentBytes, decodedSig).
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	pubKeyPEMType  = "KERNLOOM ED25519 PUBLIC KEY"
	privKeyPEMType = "KERNLOOM ED25519 PRIVATE KEY"

	// signatureMarker is appended to signed pack files.
	// Must match the constant in kernloom/pkg/core/policy/verify.go.
	signatureMarker = "\nsignature: "
)

// GenerateKeyPair creates a new Ed25519 key pair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return pub, priv, nil
}

// SavePrivateKey writes an Ed25519 private key to path in PEM format.
func SavePrivateKey(path string, key ed25519.PrivateKey) error {
	block := &pem.Block{Type: privKeyPEMType, Bytes: []byte(key)}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

// SavePublicKey writes an Ed25519 public key to path in PEM format.
func SavePublicKey(path string, key ed25519.PublicKey) error {
	block := &pem.Block{Type: pubKeyPEMType, Bytes: []byte(key)}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o644)
}

// LoadPrivateKey reads a PEM-encoded Ed25519 private key from path.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != privKeyPEMType {
		return nil, fmt.Errorf("invalid private key file %s: expected PEM type %q", path, privKeyPEMType)
	}
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: got %d bytes, want %d", len(block.Bytes), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(block.Bytes), nil
}

// SignPackYAML signs packYAML (the YAML bytes of an unsigned pack) with key
// and returns the signed file content: packYAML + signature line.
//
// The signature line "signature: <base64>\n" is appended directly after the
// trailing "\n" that yaml.v3 always adds. SplitSignature finds the split point
// by searching for "\nsignature: " — the "\n" is the last byte of packYAML,
// so the extracted content bytes are identical to packYAML (what was signed).
func SignPackYAML(packYAML []byte, key ed25519.PrivateKey) ([]byte, error) {
	// Guarantee a trailing newline so the split point is unambiguous.
	if len(packYAML) == 0 || packYAML[len(packYAML)-1] != '\n' {
		packYAML = append(packYAML, '\n')
	}
	sig := ed25519.Sign(key, packYAML)
	// Append "signature: <base64>\n" — the "\n" before "signature" is the
	// trailing "\n" of packYAML, which is included in the signed bytes.
	sigLine := []byte("signature: " + base64.StdEncoding.EncodeToString(sig) + "\n")
	return append(packYAML, sigLine...), nil
}

// VerifyPackYAML verifies the Ed25519 signature of a signed pack file.
// data is the full file content including the signature line.
func VerifyPackYAML(data []byte, pubKey ed25519.PublicKey) error {
	content, sig, found := splitSignature(data)
	if !found {
		return fmt.Errorf("pack is not signed")
	}
	if !ed25519.Verify(pubKey, content, sig) {
		return fmt.Errorf("pack signature verification failed")
	}
	return nil
}

// splitSignature separates content bytes from the appended signature.
// Mirrors kernloom/pkg/core/policy.SplitSignature exactly.
func splitSignature(data []byte) (content, sig []byte, found bool) {
	marker := []byte(signatureMarker)
	idx := lastIndex(data, marker)
	if idx < 0 {
		return data, nil, false
	}
	content = data[:idx+1]
	sigLine := trimRight(data[idx+len(marker):])
	decoded, err := base64.StdEncoding.DecodeString(string(sigLine))
	if err != nil {
		return data, nil, false
	}
	return content, decoded, true
}

func lastIndex(data, sep []byte) int {
	if len(sep) == 0 || len(data) < len(sep) {
		return -1
	}
	for i := len(data) - len(sep); i >= 0; i-- {
		if string(data[i:i+len(sep)]) == string(sep) {
			return i
		}
	}
	return -1
}

func trimRight(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
