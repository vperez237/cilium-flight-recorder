package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type stubHealth struct {
	connected bool
}

func (s stubHealth) HubbleConnected() bool { return s.connected }

func newTestServer(t *testing.T, h HealthChecker) *Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	// captureManager is nil — none of the endpoints under test invoke it.
	return NewServer(0, nil, h, logger)
}

func do(t *testing.T, s *Server, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	s.server.Handler.ServeHTTP(rec, req)
	return rec
}

func TestHealthAlwaysOK(t *testing.T) {
	s := newTestServer(t, stubHealth{connected: false})
	rec := do(t, s, http.MethodGet, "/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestReadyReflectsHubble(t *testing.T) {
	cases := []struct {
		connected bool
		wantCode  int
		wantBody  string
	}{
		{true, http.StatusOK, `"status":"ready"`},
		{false, http.StatusServiceUnavailable, `"status":"not_ready"`},
	}
	for _, tc := range cases {
		s := newTestServer(t, stubHealth{connected: tc.connected})
		rec := do(t, s, http.MethodGet, "/ready")
		if rec.Code != tc.wantCode {
			t.Errorf("connected=%v: want %d, got %d", tc.connected, tc.wantCode, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), tc.wantBody) {
			t.Errorf("connected=%v: body %q missing %q", tc.connected, rec.Body.String(), tc.wantBody)
		}
	}
}

func TestMetricsEndpointExposesPromFormat(t *testing.T) {
	s := newTestServer(t, stubHealth{})
	rec := do(t, s, http.MethodGet, "/metrics")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	// Spot-check one of the counters the metrics package registers at init.
	if !strings.Contains(body, "flight_recorder_flows_processed_total") {
		t.Errorf("/metrics response missing expected counter: %s", body)
	}
}
