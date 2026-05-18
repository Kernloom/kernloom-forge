// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package forgeapi implements the forge serve HTTP control-plane API.
//
// Auth model (Stufe 2):
//
//	KLIQ endpoints:  Authorization: Bearer <session-token>  (per-node, post-enrollment)
//	Admin endpoints: Authorization: Bearer <admin-key>  OR loopback-only when no key set
//	Enrollment:      Authorization: Bearer <one-time-token>
package forgeapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kernloom/kernloom-forge/internal/forgedb"
	"github.com/kernloom/kernloom-forge/internal/ratelimit"
)

// Server is the HTTP handler for the forge serve API.
type Server struct {
	db            *forgedb.DB
	adminKey      string // admin endpoints
	enrollLimiter *ratelimit.Limiter
	log           *log.Logger
}

// New creates a Server.
//   - adminKey: required for admin endpoints; if empty, only loopback is allowed.
func New(db *forgedb.DB, adminKey string, logger *log.Logger) *Server {
	return &Server{
		db:            db,
		adminKey:      adminKey,
		enrollLimiter: ratelimit.New(5, time.Minute), // 5 enrollments/min/IP
		log:           logger,
	}
}

// Handler returns an http.Handler with all routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// KLIQ-facing endpoints — authenticated with per-node session token.
	mux.HandleFunc("POST /api/v1/nodes/enroll", s.handleEnroll)
	mux.HandleFunc("POST /api/v1/nodes/{id}/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("GET /api/v1/nodes/{id}/policy-pack", s.handleGetPack)
	mux.HandleFunc("POST /api/v1/nodes/{id}/policy-pack/status", s.handlePackStatus)

	// Admin endpoints — require admin key or loopback source.
	mux.HandleFunc("GET /api/v1/nodes", s.withAdmin(s.handleListNodes))
	mux.HandleFunc("POST /api/v1/nodes/{id}/approve", s.withAdmin(s.handleApproveNode))
	mux.HandleFunc("POST /api/v1/nodes/{id}/revoke", s.withAdmin(s.handleRevokeNode))
	mux.HandleFunc("POST /api/v1/packs", s.withAdmin(s.handleRegisterPack))
	mux.HandleFunc("POST /api/v1/nodes/{id}/assign-pack", s.withAdmin(s.handleAssignPack))
	mux.HandleFunc("GET /api/v1/tokens", s.withAdmin(s.handleListTokens))

	return mux
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

// bearerToken extracts the token from "Authorization: Bearer <token>".
func bearerToken(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// withAdmin wraps a handler to require admin-key auth or loopback source.
func (s *Server) withAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminKey != "" {
			if bearerToken(r) != s.adminKey {
				writeError(w, http.StatusUnauthorized, "admin key required")
				return
			}
		} else {
			// No admin key configured: restrict to loopback.
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			if host != "127.0.0.1" && host != "::1" {
				writeError(w, http.StatusForbidden, "admin endpoints require loopback access when --admin-key is not set")
				return
			}
		}
		h(w, r)
	}
}

// sessionAuth validates Authorization: Bearer <session-token> for a given nodeID.
func (s *Server) sessionAuth(r *http.Request, nodeID string) bool {
	token := bearerToken(r)
	return token != "" && s.db.ValidateSessionToken(nodeID, token)
}

// generateSessionToken creates a cryptographically random 32-byte session token.
func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, APIError{Error: msg})
}

func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func remoteIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// ── POST /api/v1/nodes/enroll ─────────────────────────────────────────────────

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	// Rate limiting per IP.
	if !s.enrollLimiter.Allow(remoteIP(r)) {
		writeError(w, http.StatusTooManyRequests, "enrollment rate limit exceeded — try again later")
		return
	}

	// One-time enrollment token validation.
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "enrollment token required (Authorization: Bearer <token>)")
		return
	}
	presetNodeID, err := s.db.UseEnrollmentToken(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req NodeEnrollmentRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, "node_id is required")
		return
	}
	// If the token was pre-bound to a specific node, enforce it.
	if presetNodeID != "" && presetNodeID != req.NodeID {
		writeError(w, http.StatusForbidden,
			fmt.Sprintf("token is bound to node %q, got %q", presetNodeID, req.NodeID))
		return
	}

	if err := s.db.UpsertNode(req.NodeID, req.Mode); err != nil {
		s.log.Printf("enroll: upsert node %s: %v", req.NodeID, err)
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if req.Inventory != nil {
		_ = s.db.SaveNodeInventory(req.NodeID, req.Inventory)
	}
	if req.ConfigReport != nil {
		_ = s.db.SaveNodeConfigAsset(req.NodeID, req.ConfigReport)
	}

	// Generate and store per-node session token for all subsequent requests.
	sessionToken, err := generateSessionToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session token generation failed")
		return
	}
	_ = s.db.SetSessionToken(req.NodeID, sessionToken)

	s.db.Audit(req.NodeID, "enroll", fmt.Sprintf("mode=%s version=%s ip=%s", req.Mode, req.KLIQVersion, remoteIP(r)))
	s.log.Printf("ENROLL node=%s mode=%s ip=%s status=pending", req.NodeID, req.Mode, remoteIP(r))

	node, _ := s.db.GetNode(req.NodeID)
	writeJSON(w, http.StatusOK, NodeEnrollmentResponse{
		NodeID:       req.NodeID,
		Status:       string(node.Status),
		SessionToken: sessionToken,
		Message:      "node registered; awaiting approval",
	})
}

// ── POST /api/v1/nodes/{id}/heartbeat ────────────────────────────────────────

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	if !s.sessionAuth(r, nodeID) {
		writeError(w, http.StatusUnauthorized, "invalid session token")
		return
	}

	node, err := s.db.GetNode(nodeID)
	if err != nil {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if node.Status == forgedb.NodeRevoked {
		writeError(w, http.StatusForbidden, "node is revoked")
		return
	}

	var req HeartbeatRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	_ = s.db.TouchNode(nodeID)
	_ = s.db.RecordHeartbeat(nodeID, req.PackName, req.PackVersion, req.DriftDetected)

	if req.DriftDetected {
		s.log.Printf("HEARTBEAT node=%s pack=%s DRIFT DETECTED", nodeID, req.PackName)
		s.db.Audit(nodeID, "heartbeat_drift", fmt.Sprintf("pack=%s", req.PackName))
	}

	_, assignedName, _ := s.db.GetAssignedPack(nodeID)
	packUpdated := assignedName != "" && assignedName != req.PackName && node.Status == forgedb.NodeApproved

	writeJSON(w, http.StatusOK, HeartbeatResponse{PackUpdated: packUpdated})
}

// ── GET /api/v1/nodes/{id}/policy-pack ───────────────────────────────────────

func (s *Server) handleGetPack(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	if !s.sessionAuth(r, nodeID) {
		writeError(w, http.StatusUnauthorized, "invalid session token")
		return
	}

	node, err := s.db.GetNode(nodeID)
	if err != nil {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	switch node.Status {
	case forgedb.NodeRevoked:
		writeError(w, http.StatusForbidden, "node is revoked — pack delivery suspended")
		return
	case forgedb.NodeApproved:
		// ok
	default:
		writeError(w, http.StatusForbidden,
			fmt.Sprintf("node is %s — pack delivery requires approved status", node.Status))
		return
	}

	content, name, err := s.db.GetAssignedPack(nodeID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if content == nil {
		writeError(w, http.StatusNotFound, "no pack assigned to this node")
		return
	}

	s.log.Printf("PACK-PULL node=%s pack=%s bytes=%d", nodeID, name, len(content))
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("X-Pack-Name", name)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

// ── POST /api/v1/nodes/{id}/policy-pack/status ───────────────────────────────

func (s *Server) handlePackStatus(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	if !s.sessionAuth(r, nodeID) {
		writeError(w, http.StatusUnauthorized, "invalid session token")
		return
	}

	var req PackStatusRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	action, detail := "pack_applied", fmt.Sprintf("pack=%s", req.PackName)
	if !req.Applied {
		action = "pack_failed"
		detail = fmt.Sprintf("pack=%s error=%s", req.PackName, req.ErrorDetail)
		s.log.Printf("PACK-STATUS node=%s pack=%s FAILED: %s", nodeID, req.PackName, req.ErrorDetail)
	} else {
		s.log.Printf("PACK-STATUS node=%s pack=%s applied", nodeID, req.PackName)
	}
	s.db.Audit(nodeID, action, detail)
	w.WriteHeader(http.StatusNoContent)
}

// ── Admin endpoints ───────────────────────────────────────────────────────────

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.db.ListNodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (s *Server) handleApproveNode(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	if err := s.db.ApproveNode(nodeID); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	s.db.Audit(nodeID, "approved", "operator")
	s.log.Printf("APPROVE node=%s", nodeID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

func (s *Server) handleRevokeNode(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	if err := s.db.RevokeNode(nodeID); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	s.db.Audit(nodeID, "revoked", "operator")
	s.log.Printf("REVOKE node=%s", nodeID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleRegisterPack(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "?name= required")
		return
	}
	content, _ := readAll(r)
	if err := s.db.RegisterPack(name, content); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	s.log.Printf("PACK-REGISTER name=%s bytes=%d", name, len(content))
	writeJSON(w, http.StatusCreated, map[string]string{"name": name})
}

func (s *Server) handleAssignPack(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	packID := r.URL.Query().Get("pack")
	if packID == "" {
		writeError(w, http.StatusBadRequest, "?pack= required")
		return
	}
	if err := s.db.AssignPack(nodeID, packID, "operator"); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	s.db.Audit(nodeID, "pack_assigned", packID)
	s.log.Printf("ASSIGN node=%s pack=%s", nodeID, packID)
	writeJSON(w, http.StatusOK, map[string]string{"node_id": nodeID, "pack": packID})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.db.ListEnrollmentTokens()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func readAll(r *http.Request) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return buf, nil
}
