// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package adapterseed registers canonical adapter definitions from
// registries/adapters/ into the Forge database on startup.
// The operation is idempotent: definitions with an unchanged content hash
// are skipped. New or updated definitions are upserted.
package adapterseed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kernloom/kernloom-forge/internal/forgedb"
)

// adapterDef is the minimal structure we parse from an AdapterDefinition YAML
// to extract id, name, version, and plugin_match for DB storage.
type adapterDef struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		ID      string `yaml:"id"`
		Name    string `yaml:"name"`
		Version string `yaml:"version"`
	} `yaml:"metadata"`
	PluginMatch []string `yaml:"plugin_match"`
}

// SeedFromDir reads all YAML files from dir and upserts them as adapter
// definitions in the database. Returns the number of definitions registered
// or updated, and a list of errors for files that could not be processed.
func SeedFromDir(db *forgedb.DB, dir string, logger *log.Logger) (registered int, errs []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Printf("[adapterseed] directory %s not found — skipping", dir)
			return 0, nil
		}
		return 0, []error{fmt.Errorf("read %s: %w", dir, err)}
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		changed, err := seedFile(db, path)
		if err != nil {
			logger.Printf("[adapterseed] %s: %v", e.Name(), err)
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
			continue
		}
		if changed {
			registered++
			logger.Printf("[adapterseed] registered/updated: %s", e.Name())
		}
	}
	return registered, errs
}

func seedFile(db *forgedb.DB, path string) (changed bool, err error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read: %w", err)
	}

	var def adapterDef
	if err := yaml.Unmarshal(content, &def); err != nil {
		return false, fmt.Errorf("parse: %w", err)
	}

	// Accept both old kind (NodeDefinition) and new kind (AdapterDefinition).
	if def.Kind != "AdapterDefinition" && def.Kind != "NodeDefinition" {
		return false, fmt.Errorf("unexpected kind %q (want AdapterDefinition)", def.Kind)
	}
	if def.Metadata.ID == "" {
		return false, fmt.Errorf("metadata.id is required")
	}
	if def.Metadata.Name == "" {
		def.Metadata.Name = def.Metadata.ID
	}
	version := def.Metadata.Version
	if version == "" {
		version = "1.0.0"
	}

	h := sha256.Sum256(content)
	contentHash := hex.EncodeToString(h[:])

	pluginMatchJSON, _ := json.Marshal(def.PluginMatch)

	return db.UpsertAdapterDefinition(
		def.Metadata.ID,
		def.Metadata.Name,
		version,
		content,
		contentHash,
		string(pluginMatchJSON),
	)
}
