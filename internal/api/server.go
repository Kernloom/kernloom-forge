// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package api implements the minimal Forge control-plane HTTP API that KLIQ
// nodes use in managed mode.
//
// Endpoints:
//
//	POST /api/v1/nodes/enroll
//	POST /api/v1/nodes/{id}/heartbeat
//	POST /api/v1/nodes/{id}/inventory
//	GET  /api/v1/nodes/{id}/runtime-bundle
//	POST /api/v1/nodes/{id}/runtime-bundle/status
//	POST /api/v1/nodes/{id}/bundle-acks
//	POST /api/v1/nodes/{id}/receipts
//	POST /api/v1/nodes/{id}/risk-assessments
//	POST /api/v1/nodes/{id}/findings
//	POST /api/v1/nodes/{id}/baseline-proposals
//	POST /api/v1/nodes/{id}/graph-proposals
//	POST /api/v1/nodes/{id}/health-reports
//	POST /api/v1/nodes/{id}/decision-summaries
//	POST /api/v1/nodes/{id}/adapter-status
//	POST /api/v1/nodes/{id}/failover-status
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
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"gopkg.in/yaml.v3"
)

// NodeRecord is the server's current view of an enrolled node.
type NodeRecord struct {
	NodeID       string                          `json:"node_id" yaml:"node_id"`
	Mode         string                          `json:"mode,omitempty" yaml:"mode,omitempty"`
	KLIQVersion  string                          `json:"kliq_version,omitempty" yaml:"kliq_version,omitempty"`
	Inventory    contracts.ComponentInventory    `json:"inventory,omitempty" yaml:"inventory,omitempty"`
	ConfigReport contracts.KLIQConfigAssetReport `json:"config_report,omitempty" yaml:"config_report,omitempty"`
	EnrolledAt   time.Time                       `json:"enrolled_at" yaml:"enrolled_at"`
	LastSeenAt   time.Time                       `json:"last_seen_at" yaml:"last_seen_at"`
}

// BundleProvider is called by the server to produce the current signed bundle
// bytes for a given node ID. The server does not cache bundles itself.
type BundleProvider func(ctx context.Context, nodeID string) ([]byte, error)

// NodeAwareBundleProvider receives the enrolled node record before producing a
// bundle. Use this when bundle assignment depends on reported capabilities.
type NodeAwareBundleProvider func(ctx context.Context, node NodeRecord) ([]byte, error)

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

	// NodeAwareBundleProvider supersedes the legacy BundleProvider when set.
	NodeAwareBundleProvider NodeAwareBundleProvider
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
	nodeProvider   NodeAwareBundleProvider
	logger         *log.Logger
	requireAuth    bool
	sessionTTL     time.Duration
	tokenValidator func(nodeID, token string) error

	// In-memory auth and artifact store (MVP - not persistent).
	mu                sync.Mutex
	enrollTokens      map[string]struct{}
	sessions          map[string]nodeSession // session token -> session
	nodeSessions      map[string]string      // nodeID -> current session token
	nodes             map[string]NodeRecord
	bundleAcks        map[string][]contracts.RuntimeBundleAck
	runtimeStatuses   map[string][]contracts.RuntimeStatus
	receipts          map[string][]contracts.EnforcementReceipt
	riskAssessments   map[string][]contracts.LocalRiskAssessment
	findings          map[string][]contracts.RuntimeFinding
	baselineProposals map[string][]contracts.BaselineProposal
	graphProposals    map[string][]contracts.GraphProposal
	healthReports     map[string][]contracts.HealthReport
	decisionSummaries map[string][]contracts.RuntimeDecisionSummary
	adapterStatuses   map[string][]contracts.AdapterStatus
	failoverStatuses  map[string][]contracts.FailoverStatus
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
		mux:               http.NewServeMux(),
		bundleProvider:    provider,
		nodeProvider:      opts.NodeAwareBundleProvider,
		logger:            logger,
		requireAuth:       opts.RequireAuth,
		sessionTTL:        sessionTTL,
		tokenValidator:    opts.EnrollTokenValidator,
		enrollTokens:      enrollTokens,
		sessions:          make(map[string]nodeSession),
		nodeSessions:      make(map[string]string),
		nodes:             make(map[string]NodeRecord),
		bundleAcks:        make(map[string][]contracts.RuntimeBundleAck),
		runtimeStatuses:   make(map[string][]contracts.RuntimeStatus),
		receipts:          make(map[string][]contracts.EnforcementReceipt),
		riskAssessments:   make(map[string][]contracts.LocalRiskAssessment),
		findings:          make(map[string][]contracts.RuntimeFinding),
		baselineProposals: make(map[string][]contracts.BaselineProposal),
		graphProposals:    make(map[string][]contracts.GraphProposal),
		healthReports:     make(map[string][]contracts.HealthReport),
		decisionSummaries: make(map[string][]contracts.RuntimeDecisionSummary),
		adapterStatuses:   make(map[string][]contracts.AdapterStatus),
		failoverStatuses:  make(map[string][]contracts.FailoverStatus),
	}
	s.registerRoutes()
	return s
}

// Handler returns the HTTP handler for use with http.ListenAndServe.
func (s *Server) Handler() http.Handler { return s.mux }

// Node returns the current server-side record for an enrolled node.
func (s *Server) Node(nodeID string) (NodeRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.nodes[nodeID]
	if !ok {
		return NodeRecord{}, false
	}
	return rec, true
}

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
		NodeID       string                          `json:"node_id"`
		Mode         string                          `json:"mode"`
		KLIQVersion  string                          `json:"kliq_version,omitempty"`
		Inventory    contracts.ComponentInventory    `json:"inventory,omitempty"`
		ConfigReport contracts.KLIQConfigAssetReport `json:"config_report,omitempty"`
		EnrollKey    string                          `json:"enroll_key"`
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
	now := time.Now().UTC()
	s.nodes[req.NodeID] = NodeRecord{
		NodeID:       req.NodeID,
		Mode:         req.Mode,
		KLIQVersion:  req.KLIQVersion,
		Inventory:    req.Inventory,
		ConfigReport: req.ConfigReport,
		EnrolledAt:   now,
		LastSeenAt:   now,
	}
	s.mu.Unlock()

	s.logger.Printf("[forge-api] enroll node_id=%s mode=%s", req.NodeID, req.Mode)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"node_id":       req.NodeID,
		"status":        "approved",
		"session_token": sessionToken,
		"enrolled_at":   now.Format(time.RFC3339),
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
	case "inventory":
		s.handleInventory(w, r, nodeID)
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
	case "risk-assessments":
		s.handleRiskAssessments(w, r, nodeID)
	case "findings":
		s.handleFindings(w, r, nodeID)
	case "baseline-proposals":
		s.handleBaselineProposals(w, r, nodeID)
	case "graph-proposals":
		s.handleGraphProposals(w, r, nodeID)
	case "health-reports":
		s.handleHealthReports(w, r, nodeID)
	case "decision-summaries":
		s.handleDecisionSummaries(w, r, nodeID)
	case "adapter-status":
		s.handleAdapterStatus(w, r, nodeID)
	case "failover-status":
		s.handleFailoverStatus(w, r, nodeID)
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
	s.mu.Lock()
	if rec, ok := s.nodes[nodeID]; ok {
		rec.LastSeenAt = time.Now().UTC()
		s.nodes[nodeID] = rec
	}
	s.mu.Unlock()
	s.logger.Printf("[forge-api] heartbeat node=%s pack=%v drift=%v",
		nodeID, heartbeat["pack_name"], heartbeat["drift_detected"])
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"pack_updated": false,
		"node_status":  "approved",
	})
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var inv contracts.ComponentInventory
	if err := json.NewDecoder(r.Body).Decode(&inv); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	rec := s.nodes[nodeID]
	rec.NodeID = nodeID
	rec.Inventory = inv
	if rec.EnrolledAt.IsZero() {
		rec.EnrolledAt = time.Now().UTC()
	}
	rec.LastSeenAt = time.Now().UTC()
	s.nodes[nodeID] = rec
	s.mu.Unlock()
	s.logger.Printf("[forge-api] inventory node=%s capabilities=%d unavailable=%d",
		nodeID, len(inv.EffectiveCapabilities), len(inv.UnavailableCapabilities))
	w.WriteHeader(http.StatusOK)
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
	if s.bundleProvider == nil && s.nodeProvider == nil {
		http.Error(w, "no bundle provider configured", http.StatusServiceUnavailable)
		return
	}
	var data []byte
	var err error
	if s.nodeProvider != nil {
		node, ok := s.Node(nodeID)
		if !ok {
			http.Error(w, "node is not enrolled", http.StatusNotFound)
			return
		}
		data, err = s.nodeProvider(r.Context(), node)
	} else {
		data, err = s.bundleProvider(r.Context(), nodeID)
	}
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
	var envelope struct {
		NodeID           string `json:"node_id"`
		BundleGeneration int    `json:"bundle_generation"`
		Applied          bool   `json:"applied"`
		DriftDetected    bool   `json:"drift_detected"`
		StatusJSON       string `json:"status_json"`
		ErrorDetail      string `json:"error_detail,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	status := contracts.RuntimeStatus{
		NodeID:           firstNonEmpty(envelope.NodeID, nodeID),
		BundleGeneration: envelope.BundleGeneration,
		Applied:          envelope.Applied,
		DriftDetected:    envelope.DriftDetected,
		ErrorDetail:      envelope.ErrorDetail,
		ReportedAt:       time.Now().UTC(),
	}
	if strings.TrimSpace(envelope.StatusJSON) != "" {
		var detailed contracts.RuntimeStatus
		if err := json.Unmarshal([]byte(envelope.StatusJSON), &detailed); err == nil {
			status = detailed
			if status.NodeID == "" {
				status.NodeID = nodeID
			}
			if status.ReportedAt.IsZero() {
				status.ReportedAt = time.Now().UTC()
			}
		}
	}
	s.mu.Lock()
	s.runtimeStatuses[nodeID] = append(s.runtimeStatuses[nodeID], status)
	s.mu.Unlock()
	s.logger.Printf("[forge-api] runtime-bundle-status node=%s generation=%v applied=%v drift=%v",
		nodeID, status.BundleGeneration, status.Applied, status.DriftDetected)
	w.WriteHeader(http.StatusOK)
}

// handleBundleAck accepts bundle activation acknowledgements from KLIQ.
func (s *Server) handleBundleAck(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var ack contracts.RuntimeBundleAck
	if err := json.NewDecoder(r.Body).Decode(&ack); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if ack.NodeID == "" {
		ack.NodeID = nodeID
	}
	if ack.ReportedAt.IsZero() {
		ack.ReportedAt = time.Now().UTC()
	}
	s.mu.Lock()
	s.bundleAcks[nodeID] = append(s.bundleAcks[nodeID], ack)
	s.mu.Unlock()
	s.logger.Printf("[forge-api] bundle-ack node=%s status=%v generation=%v",
		nodeID, ack.Applied, ack.BundleGeneration)
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
		var receipt contracts.EnforcementReceipt
		if err := json.Unmarshal(raw, &receipt); err == nil {
			if receipt.NodeID == "" {
				receipt.NodeID = nodeID
			}
			s.receipts[nodeID] = append(s.receipts[nodeID], receipt)
		}
		var legacy struct {
			ID       string `json:"id"`
			Metadata struct {
				ID string `json:"id"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(raw, &legacy); err == nil {
			switch {
			case legacy.Metadata.ID != "":
				accepted = append(accepted, legacy.Metadata.ID)
			case legacy.ID != "":
				accepted = append(accepted, legacy.ID)
			case receipt.Metadata.ID != "":
				accepted = append(accepted, receipt.Metadata.ID)
			}
		}
	}
	s.mu.Unlock()

	s.logger.Printf("[forge-api] receipts node=%s count=%d", nodeID, len(body.Receipts))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"accepted": accepted})
}

func (s *Server) handleRiskAssessments(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	assessments, err := decodeJSONList[contracts.LocalRiskAssessment](r.Body, "risk_assessments")
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.riskAssessments[nodeID] = append(s.riskAssessments[nodeID], assessments...)
	s.mu.Unlock()
	s.logger.Printf("[forge-api] risk-assessments node=%s count=%d", nodeID, len(assessments))
	w.WriteHeader(http.StatusOK)
}

// handleFindings accepts RuntimeFindings from KLIQ.
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	findings, err := decodeJSONList[contracts.RuntimeFinding](r.Body, "findings")
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	for i := range findings {
		if findings[i].NodeID == "" {
			findings[i].NodeID = nodeID
		}
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
	var proposal contracts.BaselineProposal
	if err := decodeJSONOrYAML(r, &proposal); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if proposal.Metadata.NodeID == "" {
		proposal.Metadata.NodeID = nodeID
	}
	if proposal.Metadata.GeneratedAt.IsZero() {
		proposal.Metadata.GeneratedAt = time.Now().UTC()
	}
	s.mu.Lock()
	s.baselineProposals[nodeID] = append(s.baselineProposals[nodeID], proposal)
	s.mu.Unlock()
	body, _ := json.Marshal(map[string]any{"id": "proposal-" + nodeID + "-" + time.Now().Format("20060102T150405Z")})
	s.logger.Printf("[forge-api] baseline-proposal node=%s", nodeID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(body)
}

func (s *Server) handleGraphProposals(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var proposal contracts.GraphProposal
	if err := decodeJSONOrYAML(r, &proposal); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if proposal.Metadata.NodeID == "" {
		proposal.Metadata.NodeID = nodeID
	}
	if proposal.Metadata.GeneratedAt.IsZero() {
		proposal.Metadata.GeneratedAt = time.Now().UTC()
	}
	s.mu.Lock()
	s.graphProposals[nodeID] = append(s.graphProposals[nodeID], proposal)
	s.mu.Unlock()
	body, _ := json.Marshal(map[string]any{"id": "graph-proposal-" + nodeID + "-" + time.Now().Format("20060102T150405Z")})
	s.logger.Printf("[forge-api] graph-proposal node=%s edges=%d", nodeID, len(proposal.Spec.Edges))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(body)
}

func (s *Server) handleHealthReports(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reports, err := decodeJSONList[contracts.HealthReport](r.Body, "health_reports")
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	for i := range reports {
		if reports[i].NodeID == "" {
			reports[i].NodeID = nodeID
		}
		if reports[i].ReportedAt.IsZero() {
			reports[i].ReportedAt = time.Now().UTC()
		}
	}
	s.mu.Lock()
	s.healthReports[nodeID] = append(s.healthReports[nodeID], reports...)
	s.mu.Unlock()
	s.logger.Printf("[forge-api] health-reports node=%s count=%d", nodeID, len(reports))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDecisionSummaries(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	summaries, err := decodeJSONList[contracts.RuntimeDecisionSummary](r.Body, "decision_summaries")
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	for i := range summaries {
		if summaries[i].NodeID == "" {
			summaries[i].NodeID = nodeID
		}
		if summaries[i].ReportedAt.IsZero() {
			summaries[i].ReportedAt = time.Now().UTC()
		}
	}
	s.mu.Lock()
	s.decisionSummaries[nodeID] = append(s.decisionSummaries[nodeID], summaries...)
	s.mu.Unlock()
	s.logger.Printf("[forge-api] decision-summaries node=%s count=%d", nodeID, len(summaries))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAdapterStatus(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	statuses, err := decodeJSONList[contracts.AdapterStatus](r.Body, "adapter_status")
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	for i := range statuses {
		if statuses[i].NodeID == "" {
			statuses[i].NodeID = nodeID
		}
		if statuses[i].ReportedAt.IsZero() {
			statuses[i].ReportedAt = time.Now().UTC()
		}
	}
	s.mu.Lock()
	s.adapterStatuses[nodeID] = append(s.adapterStatuses[nodeID], statuses...)
	s.mu.Unlock()
	s.logger.Printf("[forge-api] adapter-status node=%s count=%d", nodeID, len(statuses))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleFailoverStatus(w http.ResponseWriter, r *http.Request, nodeID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	statuses, err := decodeJSONList[contracts.FailoverStatus](r.Body, "failover_status")
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	for i := range statuses {
		if statuses[i].NodeID == "" {
			statuses[i].NodeID = nodeID
		}
		if statuses[i].ReportedAt.IsZero() {
			statuses[i].ReportedAt = time.Now().UTC()
		}
	}
	s.mu.Lock()
	s.failoverStatuses[nodeID] = append(s.failoverStatuses[nodeID], statuses...)
	s.mu.Unlock()
	s.logger.Printf("[forge-api] failover-status node=%s count=%d", nodeID, len(statuses))
	w.WriteHeader(http.StatusOK)
}

// Receipts returns all receipts stored for a node (for testing/inspection).
func (s *Server) Receipts(nodeID string) []contracts.EnforcementReceipt {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]contracts.EnforcementReceipt, len(s.receipts[nodeID]))
	copy(out, s.receipts[nodeID])
	return out
}

func decodeJSONOrYAML(r *http.Request, out any) error {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if strings.Contains(r.Header.Get("Content-Type"), "yaml") {
		return yaml.Unmarshal(raw, out)
	}
	if err := json.Unmarshal(raw, out); err == nil {
		return nil
	}
	return yaml.Unmarshal(raw, out)
}

func decodeJSONList[T any](body io.Reader, wrapperKey string) ([]T, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	var list []T
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var wrapped map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wrapped); err == nil {
		if wrappedRaw := wrapped[wrapperKey]; len(wrappedRaw) > 0 {
			var single T
			if err := json.Unmarshal(wrappedRaw, &list); err == nil {
				return list, nil
			}
			if err := json.Unmarshal(wrappedRaw, &single); err == nil {
				return []T{single}, nil
			}
		}
	}
	var single T
	if err := json.Unmarshal(raw, &single); err == nil {
		return []T{single}, nil
	}
	return nil, fmt.Errorf("payload must be %s object or list", wrapperKey)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
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
