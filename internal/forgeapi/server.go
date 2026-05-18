// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package forgeapi implements the forge serve HTTP control-plane API.
//
// Endpoints:
//
//	POST /api/v1/nodes/enroll                    — KLIQ registers itself
//	POST /api/v1/nodes/{id}/heartbeat            — periodic status report
//	GET  /api/v1/nodes/{id}/policy-pack          — pull assigned pack
//	POST /api/v1/nodes/{id}/policy-pack/status   — report pack apply result
package forgeapi

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/kernloom/kernloom-forge/internal/forgedb"
)

// Server is the HTTP handler for the forge serve API.
type Server struct {
	db        *forgedb.DB
	enrollKey string // shared secret for Bearer auth
	log       *log.Logger
}

// New creates a Server. enrollKey is the shared secret KLIQ must present in
// the Authorization header ("Bearer <enrollKey>").
func New(db *forgedb.DB, enrollKey string, logger *log.Logger) *Server {
	return &Server{db: db, enrollKey: enrollKey, log: logger}
}

// Handler returns an http.Handler with all routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/nodes/enroll", s.handleEnroll)
	mux.HandleFunc("POST /api/v1/nodes/{id}/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("GET /api/v1/nodes/{id}/policy-pack", s.handleGetPack)
	mux.HandleFunc("POST /api/v1/nodes/{id}/policy-pack/status", s.handlePackStatus)

	// Admin endpoints (no auth for MVP — bind to loopback only in production).
	mux.HandleFunc("GET /api/v1/nodes", s.handleListNodes)
	mux.HandleFunc("POST /api/v1/nodes/{id}/approve", s.handleApproveNode)
	mux.HandleFunc("POST /api/v1/packs", s.handleRegisterPack)
	mux.HandleFunc("POST /api/v1/nodes/{id}/assign-pack", s.handleAssignPack)

	return mux
}

// ── Auth ──────────────────────────────────────────────────────────────────────

func (s *Server) auth(r *http.Request) bool {
	if s.enrollKey == "" {
		return true // no key configured → open (dev mode)
	}
	auth := r.Header.Get("Authorization")
	return strings.TrimPrefix(auth, "Bearer ") == s.enrollKey
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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

// ── POST /api/v1/nodes/enroll ─────────────────────────────────────────────────

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.auth(r) {
		writeError(w, http.StatusUnauthorized, "invalid enrollment key")
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
	s.db.Audit(req.NodeID, "enroll", fmt.Sprintf("mode=%s version=%s", req.Mode, req.KLIQVersion))
	s.log.Printf("ENROLL node=%s mode=%s status=pending", req.NodeID, req.Mode)

	node, _ := s.db.GetNode(req.NodeID)
	writeJSON(w, http.StatusOK, NodeEnrollmentResponse{
		NodeID:  req.NodeID,
		Status:  string(node.Status),
		Message: "node registered; awaiting approval",
	})
}

// ── POST /api/v1/nodes/{id}/heartbeat ────────────────────────────────────────

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !s.auth(r) {
		writeError(w, http.StatusUnauthorized, "invalid enrollment key")
		return
	}

	nodeID := r.PathValue("id")
	var req HeartbeatRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	node, err := s.db.GetNode(nodeID)
	if err != nil {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}

	_ = s.db.TouchNode(nodeID)
	_ = s.db.RecordHeartbeat(nodeID, req.PackName, req.PackVersion, req.DriftDetected)

	if req.DriftDetected {
		s.log.Printf("HEARTBEAT node=%s pack=%s DRIFT DETECTED", nodeID, req.PackName)
		s.db.Audit(nodeID, "heartbeat_drift", fmt.Sprintf("pack=%s", req.PackName))
	}

	// Check if a new pack is available.
	_, assignedName, _ := s.db.GetAssignedPack(nodeID)
	packUpdated := assignedName != "" && assignedName != req.PackName && node.Status == forgedb.NodeApproved

	writeJSON(w, http.StatusOK, HeartbeatResponse{PackUpdated: packUpdated})
}

// ── GET /api/v1/nodes/{id}/policy-pack ───────────────────────────────────────

func (s *Server) handleGetPack(w http.ResponseWriter, r *http.Request) {
	if !s.auth(r) {
		writeError(w, http.StatusUnauthorized, "invalid enrollment key")
		return
	}

	nodeID := r.PathValue("id")
	node, err := s.db.GetNode(nodeID)
	if err != nil {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if node.Status != forgedb.NodeApproved {
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
	if !s.auth(r) {
		writeError(w, http.StatusUnauthorized, "invalid enrollment key")
		return
	}

	nodeID := r.PathValue("id")
	var req PackStatusRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	action := "pack_applied"
	detail := fmt.Sprintf("pack=%s", req.PackName)
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

func (s *Server) handleRegisterPack(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "?name= query param required")
		return
	}
	content := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		content = append(content, buf[:n]...)
		if err != nil {
			break
		}
	}
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
		writeError(w, http.StatusBadRequest, "?pack= query param required")
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
