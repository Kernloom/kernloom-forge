// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package api implements the minimal Forge control-plane HTTP API that KLIQ
// nodes use in managed mode.
//
// Endpoints:
//
//	POST /api/v1/nodes/enroll
//	POST /api/v1/nodes/{id}/heartbeat
//	GET  /api/v1/nodes/{id}/runtime-bundle
//	POST /api/v1/nodes/{id}/runtime-bundle/status
//	POST /api/v1/nodes/{id}/bundle-acks
//	POST /api/v1/nodes/{id}/receipts
//	POST /api/v1/nodes/{id}/findings
//	POST /api/v1/nodes/{id}/baseline-proposals
//
// This is an MVP server. Enrollment and per-node session tokens are enforced
// in memory, but there is no persistent node registry and no multi-tenant
// isolation yet. Those are Phase 2 hardening items. The goal is to give KLIQ a
// real endpoint to pull bundles from so the managed mode path is exercised
// end-to-end.
package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// BundleProvider is called by the server to produce the current signed bundle
// bytes for a given node ID. The server does not cache bundles itself.
type BundleProvider func(ctx context.Context, nodeID string) ([]byte, error)

// ServerOptions configures the MVP control-plane server.
type ServerOptions struct {
	// EnrollTokens are one-time bootstrap tokens accepted by /nodes/enroll.
	// They are kept in memory for the MVP server. Operators can rotate them by
	// restarting forge serve with a new token set.
	EnrollTokens []string

	// RequireAuth gates enrollment and all node endpoints. NewServer keeps this
	// false for tests and low-level embedding. forge serve enables it.
	RequireAuth bool

	// EnrollTokenValidator validates and may consume a pre-registered
	// enrollment token for a node. If set, it is checked before EnrollTokens.
	EnrollTokenValidator func(nodeID, token string) error

	// SessionTTL controls how long generated node session tokens are valid.
	// Zero means 24 hours.
	SessionTTL time.Duration
}

type nodeSession struct {
	NodeID    string
	Token     string
	ExpiresAt time.Time
}

// Server is the minimal Forge HTTP API server.
type Server struct {
	mux            *http.ServeMux
	bundleProvider BundleProvider
	logger         *log.Logger
	requireAuth    bool
	sessionTTL     time.Duration
	tokenValidator func(nodeID, token string) error

	// In-memory auth, receipt and finding store (MVP - not persistent).
	mu           sync.Mutex
	enrollTokens map[string]struct{}
	sessions     map[string]nodeSession // session token -> session
	nodeSessions map[string]string      // nodeID -> current session token
	receipts     map[string][]json.RawMessage
	findings     map[string][]json.RawMessage
}

// NewServer creates a Server. bundleProvider may be nil (bundle endpoint
// returns 503); this lets the server start before bundles are compiled.
func NewServer(provider BundleProvider, logger *log.Logger) *Server {
	return NewServerWithOptions(provider, logger, ServerOptions{})
}

// NewServerWithOptions creates a Server with explicit auth options.
func NewServerWithOptions(provider BundleProvider, logger *log.Logger, opts ServerOptions) *Server {
	if logger == nil {
		logger = log.Default()
	}
	sessionTTL := opts.SessionTTL
	if sessionTTL == 0 {
		sessionTTL = 24 * time.Hour
	}
	enrollTokens := make(map[string]struct{}, len(opts.EnrollTokens))
	for _, token := range opts.EnrollTokens {
		token = strings.TrimSpace(token)
		if token != "" {
			enrollTokens[token] = struct{}{}
		}
	}
	s := &Server{
		mux:            http.NewServeMux(),
		bundleProvider: provider,
		logger:         logger,
		requireAuth:    opts.RequireAuth,
		sessionTTL:     sessionTTL,
		tokenValidator: opts.EnrollTokenValidator,
		enrollTokens:   enrollTokens,
		sessions:       make(map[string]nodeSession),
		nodeSessions:   make(map[string]string),
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
	if !s.validEnrollToken(r, req.NodeID, req.EnrollKey) {
		http.Error(w, "invalid enrollment token", http.StatusUnauthorized)
		return
	}
	sessionToken, err := randomToken()
	if err != nil {
		s.logger.Printf("[forge-api] session token generation failed node=%s: %v", req.NodeID, err)
		http.Error(w, "session token generation failed", http.StatusInternalServerError)
		return
	}
	session := nodeSession{
		NodeID:    req.NodeID,
		Token:     sessionToken,
		ExpiresAt: time.Now().UTC().Add(s.sessionTTL),
	}
	s.mu.Lock()
	if old := s.nodeSessions[req.NodeID]; old != "" {
		delete(s.sessions, old)
	}
	s.sessions[sessionToken] = session
	s.nodeSessions[req.NodeID] = sessionToken
	s.mu.Unlock()

	s.logger.Printf("[forge-api] enroll node_id=%s mode=%s", req.NodeID, req.Mode)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"node_id":       req.NodeID,
		"status":        "approved",
		"session_token": sessionToken,
		"enrolled_at":   time.Now().UTC().Format(time.RFC3339),
		"expires_at":    session.ExpiresAt.Format(time.RFC3339),
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
	if !s.authenticateNode(w, r, nodeID) {
		return
	}

	switch resource {
	case "heartbeat":
		s.handleHeartbeat(w, r, nodeID)
	case "policy-pack":
		s.handleGetPolicyPack(w, r, nodeID)
	case "policy-pack/status":
		s.handlePolicyPackStatus(w, r, nodeID)
	case "runtime-bundle":
		s.handleGetBundle(w, r, nodeID)
	case "runtime-bundle/status":
		s.handleRuntimeBundleStatus(w, r, nodeID)
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

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var heartbeat map[string]any
	if err := json.NewDecoder(r.Body).Decode(&heartbeat); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.logger.Printf("[forge-api] heartbeat node=%s pack=%v drift=%v",
		nodeID, heartbeat["pack_name"], heartbeat["drift_detected"])
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"pack_updated": false,
		"node_status":  "approved",
	})
}

func (s *Server) handleGetPolicyPack(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.logger.Printf("[forge-api] policy-pack request node=%s no local policy-pack configured", nodeID)
	http.Error(w, "no policy pack available for node", http.StatusNotFound)
}

func (s *Server) handlePolicyPackStatus(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var status map[string]any
	if err := json.NewDecoder(r.Body).Decode(&status); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.logger.Printf("[forge-api] policy-pack-status node=%s pack=%v applied=%v",
		nodeID, status["pack_name"], status["applied"])
	w.WriteHeader(http.StatusOK)
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

func (s *Server) handleRuntimeBundleStatus(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var status map[string]any
	if err := json.NewDecoder(r.Body).Decode(&status); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.logger.Printf("[forge-api] runtime-bundle-status node=%s generation=%v applied=%v drift=%v",
		nodeID, status["bundle_generation"], status["applied"], status["drift_detected"])
	w.WriteHeader(http.StatusOK)
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

func (s *Server) validEnrollToken(r *http.Request, nodeID, bodyToken string) bool {
	if !s.requireAuth {
		return true
	}
	token := bearerToken(r)
	if token == "" {
		token = strings.TrimSpace(bodyToken)
	}
	if token == "" {
		return false
	}
	if s.tokenValidator != nil {
		if err := s.tokenValidator(nodeID, token); err == nil {
			return true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.enrollTokens[token]
	return ok
}

func (s *Server) authenticateNode(w http.ResponseWriter, r *http.Request, nodeID string) bool {
	if !s.requireAuth {
		return true
	}
	token := bearerToken(r)
	if token == "" {
		http.Error(w, "missing session token", http.StatusUnauthorized)
		return false
	}
	now := time.Now().UTC()
	s.mu.Lock()
	session, ok := s.sessions[token]
	if ok && now.After(session.ExpiresAt) {
		delete(s.sessions, token)
		if s.nodeSessions[session.NodeID] == token {
			delete(s.nodeSessions, session.NodeID)
		}
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		http.Error(w, "invalid session token", http.StatusUnauthorized)
		return false
	}
	if session.NodeID != nodeID {
		http.Error(w, "session token does not match node", http.StatusForbidden)
		return false
	}
	return true
}

func bearerToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(auth, prefix))
}

func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
