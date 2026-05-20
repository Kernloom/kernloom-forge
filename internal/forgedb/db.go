// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package forgedb provides the SQLite-backed persistence layer for forge serve.
package forgedb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
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
	if err := migrateSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("forgedb: migrate: %w", err)
	}
	return &DB{db: db}, nil
}

// migrateSchema adds columns that were introduced after the initial schema.
// Each ALTER TABLE is idempotent: duplicate column errors are silently ignored.
func migrateSchema(db *sql.DB) error {
	migrations := []string{
		`ALTER TABLE nodes ADD COLUMN session_token TEXT`,
	}
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			// SQLite returns "duplicate column name" when the column already exists.
			if !isDuplicateColumn(err) {
				return fmt.Errorf("%s: %w", m, err)
			}
		}
	}
	return nil
}

func isDuplicateColumn(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "duplicate column name") ||
		strings.Contains(err.Error(), "already exists"))
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
		last_seen     DATETIME,
		session_token TEXT
	);

	CREATE TABLE IF NOT EXISTS enrollment_tokens (
		token      TEXT PRIMARY KEY,
		node_id    TEXT,
		used_at    DATETIME,
		expires_at DATETIME NOT NULL,
		created_by TEXT NOT NULL DEFAULT 'operator'
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

	CREATE TABLE IF NOT EXISTS runtime_bundles (
		id           TEXT PRIMARY KEY,
		node_id      TEXT NOT NULL,
		generation   INTEGER NOT NULL,
		content      BLOB NOT NULL,
		content_hash TEXT NOT NULL,
		issued_at    DATETIME NOT NULL,
		created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS runtime_assignments (
		node_id     TEXT PRIMARY KEY REFERENCES nodes(id),
		bundle_id   TEXT NOT NULL REFERENCES runtime_bundles(id),
		assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		assigned_by TEXT NOT NULL DEFAULT 'operator'
	);

	CREATE TABLE IF NOT EXISTS runtime_status (
		node_id        TEXT PRIMARY KEY REFERENCES nodes(id),
		generation     INTEGER NOT NULL DEFAULT 0,
		applied        INTEGER NOT NULL DEFAULT 0,
		drift_detected INTEGER NOT NULL DEFAULT 0,
		status_json    TEXT,
		error_detail   TEXT,
		reported_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS baseline_proposals (
		id            TEXT PRIMARY KEY,
		node_id       TEXT NOT NULL REFERENCES nodes(id),
		proposal_hash TEXT NOT NULL,
		content       BLOB NOT NULL,
		status        TEXT NOT NULL DEFAULT 'pending',
		created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	-- adapter_definitions stores the canonical capability declarations for each
	-- known adapter type (klshield, kliq, tcp-proxy, nginx, …).
	-- Populated automatically from registries/adapters/ on forge serve startup.
	CREATE TABLE IF NOT EXISTS adapter_definitions (
		id           TEXT PRIMARY KEY,   -- e.g. "klshield", "nginx"
		name         TEXT NOT NULL,
		version      TEXT NOT NULL DEFAULT '1.0.0',
		content      BLOB NOT NULL,      -- raw YAML of the AdapterDefinition
		content_hash TEXT NOT NULL,
		plugin_match TEXT NOT NULL DEFAULT '[]', -- JSON array of plugin IDs for auto-match
		registered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	-- node_adapter_assignments maps enrolled nodes to their adapter definition.
	-- assigned_by = 'operator' (manual) or 'auto' (matched from inventory).
	CREATE TABLE IF NOT EXISTS node_adapter_assignments (
		node_id       TEXT PRIMARY KEY REFERENCES nodes(id),
		definition_id TEXT NOT NULL REFERENCES adapter_definitions(id),
		assigned_by   TEXT NOT NULL DEFAULT 'operator',
		auto_eligible INTEGER NOT NULL DEFAULT 0, -- 1 = node allows auto-assignment
		assigned_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
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
	NodeRevoked  NodeStatus = "revoked"
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
		ON CONFLICT(id) DO UPDATE SET
			mode        = excluded.mode,
			-- Only reset to pending when the node was previously revoked.
			-- An approved node that re-enrolls (e.g. after restart) keeps its approval.
			status      = CASE WHEN status = 'revoked' THEN 'pending' ELSE status END,
			enrolled_at = CASE WHEN status = 'revoked' THEN excluded.enrolled_at ELSE enrolled_at END
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
	res, err := d.db.Exec(`UPDATE nodes SET status='approved' WHERE id=? AND status='pending'`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Check whether the node exists at all to give a better error.
		var status string
		if scanErr := d.db.QueryRow(`SELECT status FROM nodes WHERE id=?`, id).Scan(&status); scanErr != nil {
			return fmt.Errorf("node %q not found", id)
		}
		return fmt.Errorf("node %q is already %s — only pending nodes can be approved", id, status)
	}
	return nil
}

// RevokeNode sets a node's status to revoked — no pack delivery, no heartbeats accepted.
func (d *DB) RevokeNode(id string) error {
	_, err := d.db.Exec(`UPDATE nodes SET status='revoked' WHERE id=?`, id)
	return err
}

// SetSessionToken stores a node-specific session token generated at enrollment.
func (d *DB) SetSessionToken(nodeID, token string) error {
	_, err := d.db.Exec(`UPDATE nodes SET session_token=? WHERE id=?`, token, nodeID)
	return err
}

// ValidateSessionToken returns true when token matches the stored session token.
func (d *DB) ValidateSessionToken(nodeID, token string) bool {
	var stored string
	err := d.db.QueryRow(`SELECT session_token FROM nodes WHERE id=? AND status!='revoked'`, nodeID).Scan(&stored)
	return err == nil && stored == token
}

// ── Enrollment Tokens ─────────────────────────────────────────────────────────

// CreateEnrollmentToken stores a new one-time enrollment token.
func (d *DB) CreateEnrollmentToken(token, nodeID string, expiresAt time.Time) error {
	var nodeIDVal any = nodeID
	if nodeID == "" {
		nodeIDVal = nil
	}
	_, err := d.db.Exec(`
		INSERT INTO enrollment_tokens(token, node_id, expires_at)
		VALUES (?, ?, ?)
	`, token, nodeIDVal, expiresAt.UTC().Format(time.DateTime))
	return err
}

// UseEnrollmentToken validates and marks a token as used atomically.
// Returns the optional pre-set node_id (may be empty for open tokens).
// Returns error when token is invalid, expired, or already used.
func (d *DB) UseEnrollmentToken(token string) (nodeID string, err error) {
	var usedAt sql.NullString
	var expiresStr string
	var nodeIDVal sql.NullString
	row := d.db.QueryRow(`SELECT node_id, used_at, expires_at FROM enrollment_tokens WHERE token=?`, token)
	if err = row.Scan(&nodeIDVal, &usedAt, &expiresStr); err != nil {
		return "", fmt.Errorf("invalid enrollment token")
	}
	if usedAt.Valid {
		return "", fmt.Errorf("enrollment token already used")
	}
	// modernc.org/sqlite returns DATETIME columns as RFC3339 when scanned into
	// a *string, regardless of how the value was originally stored.
	expires, parseErr := time.Parse(time.RFC3339, expiresStr)
	if parseErr != nil {
		// Fallback: try the plain datetime format used by older rows.
		expires, parseErr = time.Parse(time.DateTime, expiresStr)
	}
	if parseErr != nil || time.Now().UTC().After(expires) {
		return "", fmt.Errorf("enrollment token expired")
	}
	_, err = d.db.Exec(`UPDATE enrollment_tokens SET used_at=CURRENT_TIMESTAMP WHERE token=?`, token)
	if err != nil {
		return "", err
	}
	if nodeIDVal.Valid {
		nodeID = nodeIDVal.String
	}
	return nodeID, nil
}

// ListEnrollmentTokens returns all tokens for display.
func (d *DB) ListEnrollmentTokens() ([]map[string]string, error) {
	rows, err := d.db.Query(`
		SELECT token, COALESCE(node_id,''), COALESCE(used_at,''), expires_at
		FROM enrollment_tokens ORDER BY expires_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []map[string]string
	for rows.Next() {
		var tok, nid, usedAt, exp string
		if err := rows.Scan(&tok, &nid, &usedAt, &exp); err != nil {
			return nil, err
		}
		result = append(result, map[string]string{
			"token": tok[:8] + "...", "node_id": nid, "used_at": usedAt, "expires_at": exp,
		})
	}
	return result, rows.Err()
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
// Returns an error if the pack or node does not exist in the database.
func (d *DB) AssignPack(nodeID, packID, assignedBy string) error {
	var exists int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM policy_packs WHERE id=?`, packID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return fmt.Errorf("pack %q not found — register it first with: forge pack register %s --file <path>", packID, packID)
	}
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE id=?`, nodeID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return fmt.Errorf("node %q not found — it must be enrolled before a pack can be assigned", nodeID)
	}
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

// ── Runtime bundles ───────────────────────────────────────────────────────────

// SaveRuntimeBundle stores a signed bundle and returns its ID (content hash).
func (d *DB) SaveRuntimeBundle(nodeID string, generation int, content []byte, contentHash string, issuedAt time.Time) (string, error) {
	id := contentHash[:16] // use prefix as stable short ID
	_, err := d.db.Exec(`
		INSERT OR REPLACE INTO runtime_bundles(id, node_id, generation, content, content_hash, issued_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, id, nodeID, generation, content, contentHash, issuedAt.UTC())
	return id, err
}

// AssignRuntimeBundle assigns a bundle to a node.
func (d *DB) AssignRuntimeBundle(nodeID, bundleID, assignedBy string) error {
	_, err := d.db.Exec(`
		INSERT OR REPLACE INTO runtime_assignments(node_id, bundle_id, assigned_by)
		VALUES (?, ?, ?)
	`, nodeID, bundleID, assignedBy)
	return err
}

// GetAssignedBundle returns the raw bundle content for the given node.
// Returns nil content and no error if no bundle is assigned.
func (d *DB) GetAssignedBundle(nodeID string) ([]byte, int, error) {
	row := d.db.QueryRow(`
		SELECT rb.content, rb.generation
		FROM runtime_assignments ra
		JOIN runtime_bundles rb ON ra.bundle_id = rb.id
		WHERE ra.node_id = ?
	`, nodeID)
	var content []byte
	var generation int
	if err := row.Scan(&content, &generation); err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	return content, generation, nil
}

// RecordRuntimeStatus stores the latest lifecycle status report from a node.
func (d *DB) RecordRuntimeStatus(nodeID string, generation int, applied, drift bool, statusJSON, errorDetail string) error {
	appliedInt := 0
	if applied {
		appliedInt = 1
	}
	driftInt := 0
	if drift {
		driftInt = 1
	}
	_, err := d.db.Exec(`
		INSERT OR REPLACE INTO runtime_status(node_id, generation, applied, drift_detected, status_json, error_detail, reported_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`, nodeID, generation, appliedInt, driftInt, statusJSON, errorDetail)
	return err
}

// SaveBaselineProposal stores a baseline proposal from a node.
func (d *DB) SaveBaselineProposal(nodeID, proposalHash string, content []byte) (string, error) {
	id := fmt.Sprintf("%s-%d", nodeID, time.Now().UnixNano())
	_, err := d.db.Exec(`
		INSERT INTO baseline_proposals(id, node_id, proposal_hash, content)
		VALUES (?, ?, ?, ?)
	`, id, nodeID, proposalHash, content)
	return id, err
}

// ── Pack list ─────────────────────────────────────────────────────────────────

// PackListItem holds display info for one registered pack.
type PackListItem struct {
	ID         string
	Name       string
	Size       int
	CreatedAt  string
	AssignedTo string // comma-separated node IDs, empty if unassigned
}

// ListPacks returns all registered policy packs with assignment info.
func (d *DB) ListPacks() ([]PackListItem, error) {
	rows, err := d.db.Query(`
		SELECT pp.id, pp.name, length(pp.content), pp.created_at,
		       COALESCE(GROUP_CONCAT(pa.node_id), '')
		FROM policy_packs pp
		LEFT JOIN pack_assignments pa ON pa.pack_id = pp.id
		GROUP BY pp.id
		ORDER BY pp.created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PackListItem
	for rows.Next() {
		var item PackListItem
		if err := rows.Scan(&item.ID, &item.Name, &item.Size, &item.CreatedAt, &item.AssignedTo); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ── Bundle list ───────────────────────────────────────────────────────────────

// BundleListItem holds display info for one registered bundle.
type BundleListItem struct {
	ID         string
	NodeID     string // from bundle metadata
	Generation int
	Size       int
	IssuedAt   string
	ExpiresAt  string
	AssignedTo string // node that currently has this bundle assigned
	Applied    bool   // true when KLIQ has confirmed it is running this bundle
}

// ListAllBundles returns all registered runtime bundles with assignment and active status.
func (d *DB) ListAllBundles() ([]BundleListItem, error) {
	rows, err := d.db.Query(`
		SELECT rb.id, rb.node_id, rb.generation, length(rb.content), rb.issued_at,
		       COALESCE(ra.node_id, ''),
		       COALESCE(rs.applied, 0)
		FROM runtime_bundles rb
		LEFT JOIN runtime_assignments ra ON ra.bundle_id = rb.id
		LEFT JOIN runtime_status rs ON rs.node_id = ra.node_id AND rs.generation = rb.generation
		ORDER BY rb.issued_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BundleListItem
	for rows.Next() {
		var item BundleListItem
		var applied int
		if err := rows.Scan(&item.ID, &item.NodeID, &item.Generation, &item.Size, &item.IssuedAt, &item.AssignedTo, &applied); err != nil {
			return nil, err
		}
		item.Applied = applied == 1
		out = append(out, item)
	}
	return out, rows.Err()
}

// ── Token list + revoke ───────────────────────────────────────────────────────

// TokenListItem holds display info for one enrollment token (value never exposed).
type TokenListItem struct {
	Prefix    string // first 20 chars + "..."
	NodeID    string
	ExpiresAt string
	UsedAt    string
	Status    string // active | used | expired
}

// ListTokens returns all enrollment tokens with status but without the full token value.
func (d *DB) ListTokens() ([]TokenListItem, error) {
	rows, err := d.db.Query(`
		SELECT token, COALESCE(node_id,''), expires_at, COALESCE(used_at,'')
		FROM enrollment_tokens
		ORDER BY expires_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now().UTC()
	var out []TokenListItem
	for rows.Next() {
		var tok, nid, exp, used string
		if err := rows.Scan(&tok, &nid, &exp, &used); err != nil {
			return nil, err
		}
		prefix := tok
		if len(tok) > 20 {
			prefix = tok[:20] + "..."
		}
		status := "active"
		if used != "" {
			status = "used"
		} else {
			expires, parseErr := time.Parse(time.RFC3339, exp)
			if parseErr != nil {
				expires, _ = time.Parse(time.DateTime, exp)
			}
			if now.After(expires) {
				status = "expired"
			}
		}
		out = append(out, TokenListItem{
			Prefix:    prefix,
			NodeID:    nid,
			ExpiresAt: exp,
			UsedAt:    used,
			Status:    status,
		})
	}
	return out, rows.Err()
}

// RevokeToken deletes tokens matching the given prefix. Returns the number deleted.
func (d *DB) RevokeToken(prefix string) (int, error) {
	res, err := d.db.Exec(`DELETE FROM enrollment_tokens WHERE token LIKE ? AND used_at IS NULL`, prefix+"%")
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// NodeListItem combines node info with assigned pack and bundle for display.
type NodeListItem struct {
	Node
	AssignedPack   string
	AssignedBundle string
	BundleGen      int
	LastSeen       string
	AdapterDef     string // assigned adapter definition ID (e.g. "klshield")
	AdapterBy      string // "operator" | "auto" | ""
	AutoEligible   bool   // node opted into auto-assignment
}

// ListNodesDetail returns nodes enriched with pack, bundle, and adapter definition info.
func (d *DB) ListNodesDetail() ([]NodeListItem, error) {
	rows, err := d.db.Query(`
		SELECT n.id, n.mode, n.status, n.enrolled_at, COALESCE(n.last_seen,''),
		       COALESCE(pa.pack_id,''), COALESCE(ra.bundle_id,''), COALESCE(rb.generation, 0),
		       COALESCE(naa.definition_id,''), COALESCE(naa.assigned_by,''),
		       COALESCE(naa.auto_eligible, 0)
		FROM nodes n
		LEFT JOIN pack_assignments pa ON pa.node_id = n.id
		LEFT JOIN runtime_assignments ra ON ra.node_id = n.id
		LEFT JOIN runtime_bundles rb ON rb.id = ra.bundle_id
		LEFT JOIN node_adapter_assignments naa ON naa.node_id = n.id
		ORDER BY n.enrolled_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodeListItem
	for rows.Next() {
		var item NodeListItem
		var enrolledStr, lastSeen string
		var autoElig int
		if err := rows.Scan(&item.ID, &item.Mode, &item.Status, &enrolledStr, &lastSeen,
			&item.AssignedPack, &item.AssignedBundle, &item.BundleGen,
			&item.AdapterDef, &item.AdapterBy, &autoElig); err != nil {
			return nil, err
		}
		item.LastSeen = lastSeen
		item.AutoEligible = autoElig == 1
		if t, err := time.Parse(time.RFC3339, enrolledStr); err == nil {
			item.EnrolledAt = t
		} else if t, err := time.Parse(time.DateTime, enrolledStr); err == nil {
			item.EnrolledAt = t
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ListBaselineProposals returns pending proposals for a node.
func (d *DB) ListBaselineProposals(nodeID string) ([]map[string]string, error) {
	rows, err := d.db.Query(`
		SELECT id, proposal_hash, status, created_at
		FROM baseline_proposals
		WHERE node_id = ?
		ORDER BY created_at DESC
		LIMIT 10
	`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var id, hash, status, createdAt string
		if err := rows.Scan(&id, &hash, &status, &createdAt); err != nil {
			continue
		}
		out = append(out, map[string]string{
			"id": id, "proposal_hash": hash, "status": status, "created_at": createdAt,
		})
	}
	return out, rows.Err()
}

// ── Adapter definitions ───────────────────────────────────────────────────────

// AdapterDefinition is a stored capability declaration for one adapter type.
type AdapterDefinition struct {
	ID           string
	Name         string
	Version      string
	ContentHash  string
	PluginMatch  string // JSON array of plugin IDs
	RegisteredAt string
	UpdatedAt    string
}

// UpsertAdapterDefinition inserts or updates an adapter definition.
// Idempotent: if content_hash matches the stored one, no update is performed.
// Returns true when the record was inserted or updated (i.e. content changed).
func (d *DB) UpsertAdapterDefinition(id, name, version string, content []byte, contentHash, pluginMatchJSON string) (bool, error) {
	// Check if already stored with same hash → no-op.
	var existingHash string
	err := d.db.QueryRow(`SELECT content_hash FROM adapter_definitions WHERE id = ?`, id).Scan(&existingHash)
	if err == nil && existingHash == contentHash {
		return false, nil // unchanged
	}

	_, err = d.db.Exec(`
		INSERT INTO adapter_definitions(id, name, version, content, content_hash, plugin_match, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			name         = excluded.name,
			version      = excluded.version,
			content      = excluded.content,
			content_hash = excluded.content_hash,
			plugin_match = excluded.plugin_match,
			updated_at   = CURRENT_TIMESTAMP
	`, id, name, version, content, contentHash, pluginMatchJSON)
	return err == nil, err
}

// GetAdapterDefinition returns the raw YAML content of a definition by ID.
func (d *DB) GetAdapterDefinition(id string) ([]byte, error) {
	var content []byte
	err := d.db.QueryRow(`SELECT content FROM adapter_definitions WHERE id = ?`, id).Scan(&content)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return content, err
}

// ListAdapterDefinitions returns summary info for all registered definitions.
func (d *DB) ListAdapterDefinitions() ([]AdapterDefinition, error) {
	rows, err := d.db.Query(`
		SELECT id, name, version, content_hash, plugin_match, registered_at, updated_at
		FROM adapter_definitions ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdapterDefinition
	for rows.Next() {
		var d AdapterDefinition
		if err := rows.Scan(&d.ID, &d.Name, &d.Version, &d.ContentHash, &d.PluginMatch, &d.RegisteredAt, &d.UpdatedAt); err != nil {
			continue
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// FindDefinitionByPlugin returns the definition ID whose plugin_match JSON array
// contains the given pluginID. Returns "" when no match is found.
func (d *DB) FindDefinitionByPlugin(pluginID string) (string, error) {
	// Simple LIKE search — plugin_match is a JSON array like ["builtin-klshield","klshield"].
	// For correctness we check for the quoted value inside the array.
	var defID string
	err := d.db.QueryRow(`
		SELECT id FROM adapter_definitions
		WHERE plugin_match LIKE ?
		LIMIT 1
	`, `%"`+pluginID+`"%`).Scan(&defID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return defID, err
}

// AssignAdapterDefinition assigns a definition to a node.
// assignedBy should be "operator" (manual) or "auto" (auto-matched).
func (d *DB) AssignAdapterDefinition(nodeID, definitionID, assignedBy string) error {
	_, err := d.db.Exec(`
		INSERT INTO node_adapter_assignments(node_id, definition_id, assigned_by)
		VALUES (?, ?, ?)
		ON CONFLICT(node_id) DO UPDATE SET
			definition_id = excluded.definition_id,
			assigned_by   = excluded.assigned_by,
			assigned_at   = CURRENT_TIMESTAMP
	`, nodeID, definitionID, assignedBy)
	return err
}

// SetNodeAutoEligible marks whether a node allows automatic definition assignment.
func (d *DB) SetNodeAutoEligible(nodeID string, eligible bool) error {
	v := 0
	if eligible {
		v = 1
	}
	_, err := d.db.Exec(`
		INSERT INTO node_adapter_assignments(node_id, definition_id, auto_eligible)
		VALUES (?, '', ?)
		ON CONFLICT(node_id) DO UPDATE SET auto_eligible = excluded.auto_eligible
	`, nodeID, v)
	return err
}

// GetNodeDefinition returns the definition assigned to a node, or nil if none.
func (d *DB) GetNodeDefinition(nodeID string) (*AdapterDefinition, []byte, error) {
	var def AdapterDefinition
	var content []byte
	err := d.db.QueryRow(`
		SELECT ad.id, ad.name, ad.version, ad.content_hash, ad.plugin_match,
		       ad.registered_at, ad.updated_at, ad.content
		FROM node_adapter_assignments na
		JOIN adapter_definitions ad ON na.definition_id = ad.id
		WHERE na.node_id = ?
	`, nodeID).Scan(&def.ID, &def.Name, &def.Version, &def.ContentHash, &def.PluginMatch,
		&def.RegisteredAt, &def.UpdatedAt, &content)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return &def, content, nil
}

// IsNodeAutoEligible returns true when the node has opted into auto-assignment.
func (d *DB) IsNodeAutoEligible(nodeID string) bool {
	var v int
	err := d.db.QueryRow(`
		SELECT auto_eligible FROM node_adapter_assignments WHERE node_id = ?
	`, nodeID).Scan(&v)
	return err == nil && v == 1
}
