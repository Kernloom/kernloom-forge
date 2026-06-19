// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package enrollment provides the small file-backed enrollment token store used
// by the Forge MVP control plane.
package enrollment

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	storeAPIVersion = "kernloom.io/forge/v1alpha1"
	storeKind       = "EnrollmentTokenStore"
	hashPrefix      = "sha256:"
)

// TokenRecord is a pre-registered node enrollment token. Token contains only a
// hash; the raw token is returned once by Create.
type TokenRecord struct {
	NodeID      string     `yaml:"node_id"`
	TokenHash   string     `yaml:"token_hash"`
	Description string     `yaml:"description,omitempty"`
	CreatedAt   time.Time  `yaml:"created_at"`
	ExpiresAt   time.Time  `yaml:"expires_at,omitempty"`
	UsedAt      *time.Time `yaml:"used_at,omitempty"`
}

// TokenStore is the YAML file format.
type TokenStore struct {
	APIVersion string        `yaml:"apiVersion"`
	Kind       string        `yaml:"kind"`
	Tokens     []TokenRecord `yaml:"tokens"`
}

// Store wraps a TokenStore with path and locking.
type Store struct {
	mu   sync.Mutex
	path string
	data TokenStore
}

// Load opens a token store file. A missing file becomes an empty store.
func Load(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("token store path is required")
	}
	s := &Store{
		path: path,
		data: TokenStore{
			APIVersion: storeAPIVersion,
			Kind:       storeKind,
		},
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read enrollment token store %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return s, nil
	}
	if err := yaml.Unmarshal(b, &s.data); err != nil {
		return nil, fmt.Errorf("parse enrollment token store %s: %w", path, err)
	}
	if s.data.APIVersion == "" {
		s.data.APIVersion = storeAPIVersion
	}
	if s.data.Kind == "" {
		s.data.Kind = storeKind
	}
	if s.data.Kind != storeKind {
		return nil, fmt.Errorf("invalid enrollment token store kind %q", s.data.Kind)
	}
	return s, nil
}

// Create adds a new pre-registration token and returns the raw token once.
func (s *Store) Create(nodeID string, ttl time.Duration, description string) (string, TokenRecord, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return "", TokenRecord{}, fmt.Errorf("node-id is required")
	}
	raw, err := randomToken()
	if err != nil {
		return "", TokenRecord{}, err
	}
	now := time.Now().UTC()
	rec := TokenRecord{
		NodeID:      nodeID,
		TokenHash:   tokenHash(raw),
		Description: strings.TrimSpace(description),
		CreatedAt:   now,
	}
	if ttl > 0 {
		rec.ExpiresAt = now.Add(ttl)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Tokens = append(s.data.Tokens, rec)
	if err := s.saveLocked(); err != nil {
		return "", TokenRecord{}, err
	}
	return raw, rec, nil
}

// Consume validates a raw token for a node and marks it used.
func (s *Store) Consume(nodeID, rawToken string) error {
	nodeID = strings.TrimSpace(nodeID)
	rawToken = strings.TrimSpace(rawToken)
	if nodeID == "" {
		return fmt.Errorf("node_id required")
	}
	if rawToken == "" {
		return fmt.Errorf("enrollment token required")
	}
	wantHash := tokenHash(rawToken)
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Tokens {
		rec := &s.data.Tokens[i]
		if rec.NodeID != nodeID {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(rec.TokenHash), []byte(wantHash)) != 1 {
			continue
		}
		if rec.UsedAt != nil {
			return fmt.Errorf("enrollment token already used")
		}
		if !rec.ExpiresAt.IsZero() && now.After(rec.ExpiresAt) {
			return fmt.Errorf("enrollment token expired")
		}
		rec.UsedAt = &now
		return s.saveLocked()
	}
	return fmt.Errorf("enrollment token not found")
}

func (s *Store) saveLocked() error {
	s.data.APIVersion = storeAPIVersion
	s.data.Kind = storeKind
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("create enrollment token store dir: %w", err)
	}
	b, err := yaml.Marshal(s.data)
	if err != nil {
		return fmt.Errorf("marshal enrollment token store: %w", err)
	}
	if err := os.WriteFile(s.path, b, 0o600); err != nil {
		return fmt.Errorf("write enrollment token store %s: %w", s.path, err)
	}
	return nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hashPrefix + hex.EncodeToString(sum[:])
}

func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
