// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package api implements the minimal Forge control-plane HTTP API that KLIQ
// nodes use in managed mode.
//
// Endpoints:
//
//	POST /api/v1/nodes/enroll
//	GET  /api/v1/nodes/{id}/runtime-bundle
//	POST /api/v1/nodes/{id}/bundle-acks
//	POST /api/v1/nodes/{id}/receipts
//	POST /api/v1/nodes/{id}/findings
//	POST /api/v1/nodes/{id}/baseline-proposals
//
// This is an MVP server — no persistent node registry, no auth middleware,
// no multi-tenant isolation. Those are Phase 2 hardening items. The goal is
// to give KLIQ a real endpoint to pull bundles from so the managed mode path
// is exercised end-to-end.
package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// BundleProvider is called by the server to produce the current signed bundle
// bytes for a given node ID. The server does not cache bundles itself.
type BundleProvider func(ctx context.Context, nodeID string) ([]byte, error)

// Server is the minimal Forge HTTP API server.
type Server struct {
	mux            *http.ServeMux
	bundleProvider BundleProvider
	logger         *log.Logger

	// In-memory receipt and finding store (MVP — not persistent).
	mu       sync.Mutex
	receipts map[string][]json.RawMessage // nodeID → receipts
	findings map[string][]json.RawMessage // nodeID → findings
}

// NewServer creates a Server. bundleProvider may be nil (bundle endpoint
// returns 503); this lets the server start before bundles are compiled.
func NewServer(provider BundleProvider, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	s := &Server{
		mux:            http.NewServeMux(),
		bundleProvider: provider,
		logger:         logger,
		receipts:       make(map[string][]json.RawMessage),
		findings:       make(map[string][]json.RawMessage),
	}
	s.registerRoutes()
	return s
}

// Handler returns the HTTP handler for use with http.ListenAndServe.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/api/v1/nodes/enroll", s.handleEnroll)
	s.mux.HandleFunc("/api/v1/nodes/", s.handleNodeRoutes)
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// handleEnroll accepts node enrollment requests.
// MVP: returns a static session token — no real auth yet.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		NodeID    string `json:"node_id"`
		Mode      string `json:"mode"`
		EnrollKey string `json:"enroll_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.NodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}
	s.logger.Printf("[forge-api] enroll node_id=%s mode=%s", req.NodeID, req.Mode)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"node_id":      req.NodeID,
		"session_token": "mvp-token-" + req.NodeID,
		"enrolled_at":  time.Now().UTC().Format(time.RFC3339),
	})
}

// handleNodeRoutes dispatches /api/v1/nodes/{id}/... paths.
func (s *Server) handleNodeRoutes(w http.ResponseWriter, r *http.Request) {
	// Path: /api/v1/nodes/{id}/{resource}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/"), "/", 2)
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	nodeID, resource := parts[0], parts[1]
	if nodeID == "" {
		http.NotFound(w, r)
		return
	}

	switch resource {
	case "runtime-bundle":
		s.handleGetBundle(w, r, nodeID)
	case "bundle-acks":
		s.handleBundleAck(w, r, nodeID)
	case "receipts":
		s.handleReceipts(w, r, nodeID)
	case "findings":
		s.handleFindings(w, r, nodeID)
	case "baseline-proposals":
		s.handleBaselineProposals(w, r, nodeID)
	default:
		http.NotFound(w, r)
	}
}

// handleGetBundle serves the signed RuntimeBundle for a node.
func (s *Server) handleGetBundle(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.bundleProvider == nil {
		http.Error(w, "no bundle provider configured", http.StatusServiceUnavailable)
		return
	}
	data, err := s.bundleProvider(r.Context(), nodeID)
	if err != nil {
		s.logger.Printf("[forge-api] bundle error node=%s: %v", nodeID, err)
		http.Error(w, "bundle generation failed", http.StatusInternalServerError)
		return
	}
	if len(data) == 0 {
		http.Error(w, "no bundle available for node", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleBundleAck accepts bundle activation acknowledgements from KLIQ.
func (s *Server) handleBundleAck(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var ack map[string]any
	if err := json.NewDecoder(r.Body).Decode(&ack); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.logger.Printf("[forge-api] bundle-ack node=%s status=%v generation=%v",
		nodeID, ack["status"], ack["generation"])
	w.WriteHeader(http.StatusOK)
}

// handleReceipts accepts enforcement receipts from KLIQ and returns
// the accepted IDs so KLIQ can mark them uploaded.
func (s *Server) handleReceipts(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Receipts []json.RawMessage `json:"receipts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	accepted := make([]string, 0, len(body.Receipts))
	s.mu.Lock()
	for _, raw := range body.Receipts {
		s.receipts[nodeID] = append(s.receipts[nodeID], raw)
		var r struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &r); err == nil && r.ID != "" {
			accepted = append(accepted, r.ID)
		}
	}
	s.mu.Unlock()

	s.logger.Printf("[forge-api] receipts node=%s count=%d", nodeID, len(body.Receipts))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"accepted": accepted})
}

// handleFindings accepts RuntimeFindings from KLIQ.
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var findings []json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&findings); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.findings[nodeID] = append(s.findings[nodeID], findings...)
	s.mu.Unlock()
	s.logger.Printf("[forge-api] findings node=%s count=%d", nodeID, len(findings))
	w.WriteHeader(http.StatusOK)
}

// handleBaselineProposals accepts baseline proposals from KLIQ.
func (s *Server) handleBaselineProposals(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, _ := json.Marshal(map[string]any{"id": "proposal-" + nodeID + "-" + time.Now().Format("20060102T150405Z")})
	s.logger.Printf("[forge-api] baseline-proposal node=%s", nodeID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(body)
}

// Receipts returns all receipts stored for a node (for testing/inspection).
func (s *Server) Receipts(nodeID string) []json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]json.RawMessage, len(s.receipts[nodeID]))
	copy(out, s.receipts[nodeID])
	return out
}
