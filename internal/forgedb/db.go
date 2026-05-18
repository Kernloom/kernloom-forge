// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package forgedb provides the SQLite-backed persistence layer for forge serve.
package forgedb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// DB wraps the SQLite connection and provides typed operations.
type DB struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path and applies the schema.
func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("forgedb: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1) // SQLite: single writer
	if err := applySchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("forgedb: schema: %w", err)
	}
	return &DB{db: db}, nil
}

// Close closes the underlying database connection.
func (d *DB) Close() error { return d.db.Close() }

// ── Schema ────────────────────────────────────────────────────────────────────

func applySchema(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS nodes (
		id            TEXT PRIMARY KEY,
		mode          TEXT NOT NULL,
		status        TEXT NOT NULL DEFAULT 'pending',
		enrolled_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_seen     DATETIME
	);

	CREATE TABLE IF NOT EXISTS node_inventory (
		node_id        TEXT PRIMARY KEY REFERENCES nodes(id),
		inventory_json TEXT NOT NULL,
		updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS node_config_assets (
		node_id      TEXT PRIMARY KEY REFERENCES nodes(id),
		report_json  TEXT NOT NULL,
		config_hash  TEXT,
		updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS policy_packs (
		id         TEXT PRIMARY KEY,
		name       TEXT NOT NULL,
		content    BLOB NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS pack_assignments (
		node_id     TEXT PRIMARY KEY REFERENCES nodes(id),
		pack_id     TEXT REFERENCES policy_packs(id),
		assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		assigned_by TEXT NOT NULL DEFAULT 'operator'
	);

	CREATE TABLE IF NOT EXISTS heartbeats (
		id             INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id        TEXT REFERENCES nodes(id),
		timestamp      DATETIME NOT NULL,
		pack_name      TEXT,
		pack_version   TEXT,
		drift_detected INTEGER NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS audit_log (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		node_id   TEXT,
		action    TEXT NOT NULL,
		detail    TEXT
	);
	`)
	return err
}

// ── Node ──────────────────────────────────────────────────────────────────────

// NodeStatus represents the lifecycle state of an enrolled node.
type NodeStatus string

const (
	NodePending  NodeStatus = "pending"
	NodeApproved NodeStatus = "approved"
	NodeRejected NodeStatus = "rejected"
)

// Node is the stored representation of an enrolled KLIQ instance.
type Node struct {
	ID         string
	Mode       string
	Status     NodeStatus
	EnrolledAt time.Time
	LastSeen   *time.Time
}

// UpsertNode inserts or updates a node record (used on enrollment and heartbeat).
func (d *DB) UpsertNode(id, mode string) error {
	_, err := d.db.Exec(`
		INSERT INTO nodes(id, mode, status, enrolled_at)
		VALUES (?, ?, 'pending', CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET mode=excluded.mode
	`, id, mode)
	return err
}

// TouchNode updates last_seen for heartbeat tracking.
func (d *DB) TouchNode(id string) error {
	_, err := d.db.Exec(`UPDATE nodes SET last_seen=CURRENT_TIMESTAMP WHERE id=?`, id)
	return err
}

// GetNode returns the node record or sql.ErrNoRows if not found.
func (d *DB) GetNode(id string) (Node, error) {
	var n Node
	var lastSeen sql.NullString
	row := d.db.QueryRow(`SELECT id, mode, status, enrolled_at, last_seen FROM nodes WHERE id=?`, id)
	var enrolledStr string
	if err := row.Scan(&n.ID, &n.Mode, &n.Status, &enrolledStr, &lastSeen); err != nil {
		return n, err
	}
	n.EnrolledAt, _ = time.Parse(time.DateTime, enrolledStr)
	if lastSeen.Valid {
		t, _ := time.Parse(time.DateTime, lastSeen.String)
		n.LastSeen = &t
	}
	return n, nil
}

// ListNodes returns all nodes ordered by enrollment time.
func (d *DB) ListNodes() ([]Node, error) {
	rows, err := d.db.Query(`SELECT id, mode, status, enrolled_at, last_seen FROM nodes ORDER BY enrolled_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []Node
	for rows.Next() {
		var n Node
		var enrolledStr string
		var lastSeen sql.NullString
		if err := rows.Scan(&n.ID, &n.Mode, &n.Status, &enrolledStr, &lastSeen); err != nil {
			return nil, err
		}
		n.EnrolledAt, _ = time.Parse(time.DateTime, enrolledStr)
		if lastSeen.Valid {
			t, _ := time.Parse(time.DateTime, lastSeen.String)
			n.LastSeen = &t
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

// ApproveNode sets a node's status to approved.
func (d *DB) ApproveNode(id string) error {
	_, err := d.db.Exec(`UPDATE nodes SET status='approved' WHERE id=?`, id)
	return err
}

// ── Inventory + Config ────────────────────────────────────────────────────────

// SaveNodeInventory stores the ComponentRuntimeInventory JSON for a node.
func (d *DB) SaveNodeInventory(nodeID string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`
		INSERT INTO node_inventory(node_id, inventory_json, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(node_id) DO UPDATE SET inventory_json=excluded.inventory_json, updated_at=CURRENT_TIMESTAMP
	`, nodeID, string(b))
	return err
}

// SaveNodeConfigAsset stores the KliqConfigAssetReport JSON for a node.
func (d *DB) SaveNodeConfigAsset(nodeID string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`
		INSERT INTO node_config_assets(node_id, report_json, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(node_id) DO UPDATE SET report_json=excluded.report_json, updated_at=CURRENT_TIMESTAMP
	`, nodeID, string(b))
	return err
}

// ── Policy Packs ──────────────────────────────────────────────────────────────

// RegisterPack stores a signed pack YAML file identified by name.
func (d *DB) RegisterPack(name string, content []byte) error {
	_, err := d.db.Exec(`
		INSERT INTO policy_packs(id, name, content, created_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET content=excluded.content, created_at=CURRENT_TIMESTAMP
	`, name, name, content)
	return err
}

// AssignPack assigns a registered pack to a node.
func (d *DB) AssignPack(nodeID, packID, assignedBy string) error {
	_, err := d.db.Exec(`
		INSERT INTO pack_assignments(node_id, pack_id, assigned_at, assigned_by)
		VALUES (?, ?, CURRENT_TIMESTAMP, ?)
		ON CONFLICT(node_id) DO UPDATE SET pack_id=excluded.pack_id, assigned_at=CURRENT_TIMESTAMP, assigned_by=excluded.assigned_by
	`, nodeID, packID, assignedBy)
	return err
}

// GetAssignedPack returns the signed pack content for a node, or nil if no pack is assigned.
func (d *DB) GetAssignedPack(nodeID string) ([]byte, string, error) {
	var content []byte
	var name string
	err := d.db.QueryRow(`
		SELECT pp.content, pp.name
		FROM pack_assignments pa
		JOIN policy_packs pp ON pp.id = pa.pack_id
		WHERE pa.node_id = ?
	`, nodeID).Scan(&content, &name)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	return content, name, err
}

// ── Heartbeats ────────────────────────────────────────────────────────────────

// RecordHeartbeat inserts a heartbeat record for audit purposes.
func (d *DB) RecordHeartbeat(nodeID, packName, packVersion string, drift bool) error {
	driftInt := 0
	if drift {
		driftInt = 1
	}
	_, err := d.db.Exec(`
		INSERT INTO heartbeats(node_id, timestamp, pack_name, pack_version, drift_detected)
		VALUES (?, CURRENT_TIMESTAMP, ?, ?, ?)
	`, nodeID, packName, packVersion, driftInt)
	return err
}

// ── Audit ─────────────────────────────────────────────────────────────────────

// Audit inserts an audit log entry.
func (d *DB) Audit(nodeID, action, detail string) {
	_, _ = d.db.Exec(`
		INSERT INTO audit_log(node_id, action, detail)
		VALUES (?, ?, ?)
	`, nodeID, action, detail)
}
