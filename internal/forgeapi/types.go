// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package forgeapi

import "time"

// ── Enrollment ────────────────────────────────────────────────────────────────

// NodeEnrollmentRequest is sent by KLIQ on startup to register with Forge.
type NodeEnrollmentRequest struct {
	NodeID       string         `json:"node_id"`
	Mode         string         `json:"mode"` // standalone | managed
	KLIQVersion  string         `json:"kliq_version,omitempty"`
	Inventory    map[string]any `json:"inventory,omitempty"`     // ComponentRuntimeInventory
	ConfigReport map[string]any `json:"config_report,omitempty"` // KliqConfigAssetReport
}

// NodeEnrollmentResponse is returned by Forge after enrollment.
// SessionToken is a per-node credential for all subsequent requests —
// it replaces the one-time enrollment token after first use.
type NodeEnrollmentResponse struct {
	NodeID       string `json:"node_id"`
	Status       string `json:"status"`                 // pending | approved | rejected
	SessionToken string `json:"session_token"`          // use for heartbeat + pack-pull
	Message      string `json:"message,omitempty"`
}

// ── Heartbeat ─────────────────────────────────────────────────────────────────

// HeartbeatRequest is sent by KLIQ periodically to report operational status.
type HeartbeatRequest struct {
	NodeID        string    `json:"node_id"`
	Timestamp     time.Time `json:"timestamp"`
	PackName      string    `json:"pack_name,omitempty"`
	PackVersion   string    `json:"pack_version,omitempty"`
	DriftDetected bool      `json:"drift_detected"`
}

// HeartbeatResponse carries optional directives back to KLIQ.
type HeartbeatResponse struct {
	// PackUpdated is true when a new pack is available via GET /policy-pack.
	PackUpdated bool   `json:"pack_updated"`
	Message     string `json:"message,omitempty"`
}

// ── Pack status ───────────────────────────────────────────────────────────────

// PackStatusRequest is sent after KLIQ has applied a policy pack.
type PackStatusRequest struct {
	NodeID      string `json:"node_id"`
	PackName    string `json:"pack_name"`
	Applied     bool   `json:"applied"`
	ErrorDetail string `json:"error_detail,omitempty"`
}

// ── Error ─────────────────────────────────────────────────────────────────────

// APIError is the standard error response body.
type APIError struct {
	Error string `json:"error"`
}
