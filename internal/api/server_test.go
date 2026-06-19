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

	"github.com/kernloom/kernloom-forge/internal/api"
)

func TestEnroll(t *testing.T) {
	srv := api.NewServer(nil, nil)
	body, _ := json.Marshal(map[string]any{"node_id": "test-node", "mode": "managed"})
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

func TestHealthz(t *testing.T) {
	srv := api.NewServer(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rw := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("healthz: got %d, want 200", rw.Code)
	}
}
