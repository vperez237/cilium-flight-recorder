package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
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

// doJSON posts a JSON body.
func doJSON(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
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

func TestCaptureRejectsBadInput(t *testing.T) {
	s := newTestServer(t, stubHealth{})
	cases := []struct {
		name string
		body string
		want string // substring expected in the error response
	}{
		{"malformed json", `not json`, "invalid JSON"},
		{"bad src cidr", `{"srcCIDR":"not-an-ip","dstCIDR":"10.0.0.1"}`, "srcCIDR"},
		{"bad dst cidr", `{"srcCIDR":"10.0.0.1","dstCIDR":"10.0.0.0/99"}`, "dstCIDR"},
		{"port too high", `{"srcCIDR":"10.0.0.1","dstCIDR":"10.0.0.2","dstPort":70000}`, "dstPort"},
		{"bad protocol", `{"srcCIDR":"10.0.0.1","dstCIDR":"10.0.0.2","protocol":"SCTP"}`, "protocol"},
		{"negative duration", `{"srcCIDR":"10.0.0.1","dstCIDR":"10.0.0.2","durationSeconds":-5}`, "durationSeconds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doJSON(t, s, http.MethodPost, "/capture", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d (body: %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Errorf("body %q missing %q", rec.Body.String(), tc.want)
			}
		})
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := []struct {
		in       string
		want     string
		wantErr  bool
	}{
		{"", "", false},
		{"10.0.1.5", "10.0.1.5", false},
		{"10.0.1.5/32", "10.0.1.5", false},
		{"10.0.0.0/24", "10.0.0.0", false},
		{"::1", "::1", false},
		{"fe80::1/64", "fe80::1", false},
		{"not-an-ip", "", true},
		{"10.0.0.1/99", "", true},
		{"10.0.0.256", "", true},
	}
	for _, tc := range cases {
		got, err := normalizeIP(tc.in, "test")
		if tc.wantErr && err == nil {
			t.Errorf("normalizeIP(%q): expected error, got %q", tc.in, got)
			continue
		}
		if !tc.wantErr && err != nil {
			t.Errorf("normalizeIP(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("normalizeIP(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestListCapturesPagination(t *testing.T) {
	s := newTestServer(t, stubHealth{})

	// Seed 12 captures with staggered timestamps so newest-first is unambiguous.
	base := time.Now().Add(-time.Hour)
	triggers := []string{"drop", "http_error", "dns_failure", "latency", "manual"}
	for i := 0; i < 12; i++ {
		s.captures = append(s.captures, CaptureEntry{
			Trigger:   triggers[i%len(triggers)],
			Reason:    "seed",
			DstPort:   uint32(8000 + i),
			StartTime: base.Add(time.Duration(i) * time.Minute),
		})
	}

	type listResp []CaptureEntry

	decode := func(t *testing.T, rec *httptest.ResponseRecorder) listResp {
		t.Helper()
		var got listResp
		body, _ := io.ReadAll(rec.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode %q: %v", body, err)
		}
		return got
	}

	t.Run("default returns all (12 <= defaultLimit)", func(t *testing.T) {
		rec := do(t, s, http.MethodGet, "/captures")
		if rec.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", rec.Code)
		}
		got := decode(t, rec)
		if len(got) != 12 {
			t.Errorf("want 12, got %d", len(got))
		}
		// Newest first: last appended (port 8011) should come first.
		if got[0].DstPort != 8011 {
			t.Errorf("first entry port = %d, want 8011 (newest first)", got[0].DstPort)
		}
		if rec.Header().Get("X-Total-Count") != "12" {
			t.Errorf("X-Total-Count = %q, want 12", rec.Header().Get("X-Total-Count"))
		}
	})

	t.Run("limit", func(t *testing.T) {
		rec := do(t, s, http.MethodGet, "/captures?limit=3")
		got := decode(t, rec)
		if len(got) != 3 {
			t.Errorf("want 3, got %d", len(got))
		}
		// Newest three: ports 8011, 8010, 8009.
		wantPorts := []uint32{8011, 8010, 8009}
		for i, p := range wantPorts {
			if got[i].DstPort != p {
				t.Errorf("got[%d].DstPort = %d, want %d", i, got[i].DstPort, p)
			}
		}
	})

	t.Run("offset", func(t *testing.T) {
		rec := do(t, s, http.MethodGet, "/captures?limit=2&offset=2")
		got := decode(t, rec)
		if len(got) != 2 {
			t.Fatalf("want 2, got %d", len(got))
		}
		if got[0].DstPort != 8009 || got[1].DstPort != 8008 {
			t.Errorf("offset=2 page: got ports %d,%d want 8009,8008", got[0].DstPort, got[1].DstPort)
		}
	})

	t.Run("trigger filter", func(t *testing.T) {
		rec := do(t, s, http.MethodGet, "/captures?trigger=drop")
		got := decode(t, rec)
		for _, e := range got {
			if e.Trigger != "drop" {
				t.Errorf("filtered response contains non-drop entry: %+v", e)
			}
		}
		// Of 12 seeded entries, indices 0,5,10 are drops => 3.
		if len(got) != 3 {
			t.Errorf("want 3 drop entries, got %d", len(got))
		}
		if rec.Header().Get("X-Total-Count") != "3" {
			t.Errorf("X-Total-Count after filter = %q, want 3", rec.Header().Get("X-Total-Count"))
		}
	})

	t.Run("offset beyond total returns empty", func(t *testing.T) {
		rec := do(t, s, http.MethodGet, "/captures?offset=100")
		got := decode(t, rec)
		if len(got) != 0 {
			t.Errorf("want empty page, got %d entries", len(got))
		}
	})

	t.Run("bad limit rejected", func(t *testing.T) {
		rec := do(t, s, http.MethodGet, "/captures?limit=9999")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("want 400 for out-of-range limit, got %d", rec.Code)
		}
	})

	t.Run("non-integer limit rejected", func(t *testing.T) {
		rec := do(t, s, http.MethodGet, "/captures?limit=abc")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("want 400 for non-integer limit, got %d", rec.Code)
		}
	})
}
