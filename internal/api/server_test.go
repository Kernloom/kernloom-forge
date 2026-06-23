// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom-forge/internal/api"
)

func TestEnroll(t *testing.T) {
	srv := api.NewServer(nil, nil)
	body, _ := json.Marshal(map[string]any{
		"node_id":      "test-node",
		"mode":         "managed",
		"kliq_version": "0.4.0",
		"inventory": map[string]any{
			"labels": map[string]string{
				"role":    "edge-gateway",
				"env":     "production",
				"service": "public-edge",
			},
			"effective_capabilities": []map[string]any{{
				"id":     "enforce.traffic.rate_limit",
				"status": "available",
			}},
		},
		"config_report": map[string]any{
			"adapters": []map[string]any{{
				"id":      "klshield",
				"enabled": true,
			}},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("enroll: got %d, want 200", rw.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(rw.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["node_id"] != "test-node" {
		t.Errorf("node_id = %v, want test-node", resp["node_id"])
	}
	if resp["session_token"] == "" {
		t.Error("session_token should be returned")
	}
	node, ok := srv.Node("test-node")
	if !ok {
		t.Fatal("node record should be stored")
	}
	if node.KLIQVersion != "0.4.0" ||
		len(node.Inventory.EffectiveCapabilities) != 1 ||
		len(node.ConfigReport.Adapters) != 1 {
		t.Fatalf("node record not populated: %#v", node)
	}
	if node.Inventory.Labels["role"] != "edge-gateway" ||
		node.Inventory.Labels["env"] != "production" ||
		node.Inventory.Labels["service"] != "public-edge" {
		t.Fatalf("node labels not populated: %#v", node.Inventory.Labels)
	}
}

func TestNodeAwareBundleProviderReceivesEnrollmentRecord(t *testing.T) {
	var got api.NodeRecord
	srv := api.NewServerWithOptions(nil, nil, api.ServerOptions{
		NodeAwareBundleProvider: func(_ context.Context, node api.NodeRecord) ([]byte, error) {
			got = node
			return []byte("--- node aware bundle ---"), nil
		},
	})
	body, _ := json.Marshal(map[string]any{
		"node_id": "test-node",
		"inventory": map[string]any{
			"labels": map[string]string{
				"role": "edge-gateway",
				"env":  "production",
			},
			"effective_capabilities": []map[string]any{{
				"id":     "enforce.traffic.rate_limit",
				"status": "available",
			}},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("enroll: got %d", rw.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/nodes/test-node/runtime-bundle", nil)
	rw = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("bundle: got %d", rw.Code)
	}
	if got.NodeID != "test-node" || len(got.Inventory.EffectiveCapabilities) != 1 {
		t.Fatalf("provider got bad node record: %#v", got)
	}
	if got.Inventory.Labels["role"] != "edge-gateway" || got.Inventory.Labels["env"] != "production" {
		t.Fatalf("provider got bad labels: %#v", got.Inventory.Labels)
	}
}

func TestEnroll_WithTokenAuth(t *testing.T) {
	bundleData := []byte("--- fake signed bundle ---")
	provider := func(_ context.Context, nodeID string) ([]byte, error) {
		if nodeID != "test-node" {
			return nil, nil
		}
		return bundleData, nil
	}
	srv := api.NewServerWithOptions(provider, nil, api.ServerOptions{
		RequireAuth:  true,
		EnrollTokens: []string{"enroll-secret"},
	})

	body, _ := json.Marshal(map[string]any{"node_id": "test-node", "mode": "managed"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("missing token enroll: got %d, want 401", rw.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/nodes/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer enroll-secret")
	rw = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("enroll: got %d, want 200", rw.Code)
	}
	var enrollResp map[string]any
	if err := json.NewDecoder(rw.Body).Decode(&enrollResp); err != nil {
		t.Fatal(err)
	}
	sessionToken, _ := enrollResp["session_token"].(string)
	if sessionToken == "" {
		t.Fatal("session_token should be returned")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/nodes/test-node/runtime-bundle", nil)
	rw = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("missing session bundle: got %d, want 401", rw.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/nodes/test-node/runtime-bundle", nil)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	rw = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("bundle with session: got %d, want 200", rw.Code)
	}
	if got := rw.Body.Bytes(); string(got) != string(bundleData) {
		t.Errorf("body = %q, want %q", got, bundleData)
	}
}

func TestEnroll_WithBodyEnrollKey(t *testing.T) {
	srv := api.NewServerWithOptions(nil, nil, api.ServerOptions{
		RequireAuth:  true,
		EnrollTokens: []string{"body-secret"},
	})
	body, _ := json.Marshal(map[string]any{
		"node_id":    "test-node",
		"mode":       "managed",
		"enroll_key": "body-secret",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("enroll with body key: got %d, want 200", rw.Code)
	}
}

func TestGetBundle_NoProvider(t *testing.T) {
	srv := api.NewServer(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/test-node/runtime-bundle", nil)
	rw := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rw.Code)
	}
}

func TestGetBundle_WithProvider(t *testing.T) {
	bundleData := []byte("--- fake signed bundle ---")
	provider := func(_ context.Context, nodeID string) ([]byte, error) {
		if nodeID == "test-node" {
			return bundleData, nil
		}
		return nil, nil
	}
	srv := api.NewServer(provider, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/test-node/runtime-bundle", nil)
	rw := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rw.Code)
	}
	if got := rw.Body.Bytes(); string(got) != string(bundleData) {
		t.Errorf("body = %q, want %q", got, bundleData)
	}
}

func TestReceipts(t *testing.T) {
	srv := api.NewServer(nil, nil)

	// POST two receipts.
	body, _ := json.Marshal(map[string]any{
		"receipts": []map[string]any{
			{"id": "receipt-1", "status": "applied"},
			{"id": "receipt-2", "status": "skipped"},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/n1/receipts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("receipts POST: got %d, want 200", rw.Code)
	}

	// Accepted IDs should be returned.
	var resp map[string]any
	if err := json.NewDecoder(rw.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	accepted, _ := resp["accepted"].([]any)
	if len(accepted) != 2 {
		t.Errorf("accepted count = %d, want 2", len(accepted))
	}

	// Server should have stored them.
	stored := srv.Receipts("n1")
	if len(stored) != 2 {
		t.Errorf("stored count = %d, want 2", len(stored))
	}
}

func TestNodeArtifactEndpoints(t *testing.T) {
	srv := api.NewServer(nil, nil)
	now := time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		path string
		body any
		want int
	}{
		{
			path: "/api/v1/nodes/n1/inventory",
			body: contracts.ComponentInventory{
				APIVersion: contracts.RuntimeAPIVersion,
				Kind:       contracts.KindComponentInventory,
				Metadata:   contracts.ComponentInventoryMetadata{ID: "klshield-n1", Timestamp: now},
				ControlledBy: contracts.ComponentInventoryControl{
					NodeID: "n1",
				},
				EffectiveCapabilities: []contracts.ComponentCapabilityStatus{{
					ID:     "enforce.traffic.rate_limit",
					Status: "available",
				}},
			},
			want: http.StatusOK,
		},
		{
			path: "/api/v1/nodes/n1/risk-assessments",
			body: map[string]any{"risk_assessments": []contracts.LocalRiskAssessment{{
				TypeMeta:   contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindLocalRiskAssessment},
				Metadata:   contracts.ObjectMeta{ID: "risk-1"},
				Subject:    contracts.EntityRef{Kind: "source", ID: "10.0.0.8"},
				Score:      72,
				Level:      contracts.RiskHigh,
				Confidence: 0.9,
				ValidUntil: now.Add(5 * time.Minute),
				Model:      "fixture-local-risk",
			}}},
			want: http.StatusOK,
		},
		{
			path: "/api/v1/nodes/n1/health-reports",
			body: contracts.HealthReport{
				TypeMeta:   contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindHealthReport},
				NodeID:     "n1",
				Status:     "healthy",
				Healthy:    true,
				ReportedAt: now,
			},
			want: http.StatusOK,
		},
		{
			path: "/api/v1/nodes/n1/decision-summaries",
			body: contracts.RuntimeDecisionSummary{
				TypeMeta:      contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindRuntimeDecisionSummary},
				NodeID:        "n1",
				WindowStart:   now.Add(-time.Minute),
				WindowEnd:     now,
				DecisionCount: 3,
				ByLevel:       map[string]int{"soft": 2, "block": 1},
				ReportedAt:    now,
			},
			want: http.StatusOK,
		},
		{
			path: "/api/v1/nodes/n1/adapter-status",
			body: []contracts.AdapterStatus{{
				TypeMeta:           contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindAdapterStatus},
				NodeID:             "n1",
				AdapterID:          "klshield",
				Kind:               "pep",
				Healthy:            true,
				ActiveCapabilities: []string{"enforce.traffic.rate_limit"},
				ReportedAt:         now,
			}},
			want: http.StatusOK,
		},
		{
			path: "/api/v1/nodes/n1/failover-status",
			body: contracts.FailoverStatus{
				TypeMeta:       contracts.TypeMeta{APIVersion: contracts.RuntimeAPIVersion, Kind: contracts.KindFailoverStatus},
				NodeID:         "n1",
				ForgeReachable: true,
				ActiveMode:     "normal",
				ReportedAt:     now,
			},
			want: http.StatusOK,
		},
		{
			path: "/api/v1/nodes/n1/baseline-proposals",
			body: contracts.BaselineProposal{
				APIVersion: contracts.RuntimeAPIVersion,
				Kind:       contracts.KindBaselineProposal,
				Metadata:   contracts.ProposalMetadata{NodeID: "n1", GeneratedAt: now},
				Spec: contracts.BaselineProposalSpec{
					BootstrapAutotune: contracts.BootstrapProposalSummary{
						Phase:           "steady",
						ObservedSeconds: 3600,
						CleanRatio:      0.99,
						Triggers:        contracts.TriggerSet{PPS: 100, SYN: 20, Scan: 5, BPS: 1000},
					},
					SourceBaselineSummary: contracts.SourceProposalSummary{
						TrackedSources:        2,
						HighConfidenceSources: 1,
						AverageConfidence:     0.8,
					},
				},
			},
			want: http.StatusCreated,
		},
		{
			path: "/api/v1/nodes/n1/graph-proposals",
			body: contracts.GraphProposal{
				APIVersion: contracts.RuntimeAPIVersion,
				Kind:       contracts.KindGraphProposal,
				Metadata:   contracts.ProposalMetadata{NodeID: "n1", GeneratedAt: now},
				Spec: contracts.GraphProposalSpec{
					Summary: contracts.GraphProposalSummary{LearnedEdges: 1},
				},
			},
			want: http.StatusCreated,
		},
	}
	for _, tt := range tests {
		body, _ := json.Marshal(tt.body)
		req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rw := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rw, req)
		if rw.Code != tt.want {
			t.Fatalf("%s: got %d, want %d", tt.path, rw.Code, tt.want)
		}
	}
}

func TestHealthz(t *testing.T) {
	srv := api.NewServer(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rw := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("healthz: got %d, want 200", rw.Code)
	}
}
