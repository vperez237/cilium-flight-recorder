package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vperez237/cilium-flight-recorder/pkg/capture"
	"github.com/vperez237/cilium-flight-recorder/pkg/detector"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Pagination limits for /captures. A hard cap stops a single request from
// returning the entire in-memory ring; the server keeps the last 100
// completed captures, so defaultLimit=100 matches the old behaviour.
const (
	defaultListLimit = 100
	maxListLimit     = 1000
)

// Protocols accepted by /capture. These match what the Cilium recorder
// filter understands (see capture.protocolToNumber).
var allowedProtocols = map[string]struct{}{
	"TCP": {}, "UDP": {}, "ICMPv4": {}, "ICMPv6": {},
}

// HealthChecker reports the liveness state of upstream dependencies.
// The API server uses it to answer /ready. Implementations must be safe
// for concurrent use.
type HealthChecker interface {
	// HubbleConnected returns true while the Hubble gRPC stream is established.
	HubbleConnected() bool
}

// CaptureRequestBody is the JSON body for POST /capture.
type CaptureRequestBody struct {
	SrcCIDR         string `json:"srcCIDR"`
	DstCIDR         string `json:"dstCIDR"`
	DstPort         uint32 `json:"dstPort"`
	Protocol        string `json:"protocol"`
	DurationSeconds int    `json:"durationSeconds"`
}

// CaptureEntry stores info about a completed capture for listing.
type CaptureEntry struct {
	Trigger   string    `json:"trigger"`
	Reason    string    `json:"reason"`
	SrcIP     string    `json:"srcIP"`
	DstIP     string    `json:"dstIP"`
	DstPort   uint32    `json:"dstPort"`
	FilePath  string    `json:"filePath"`
	StartTime time.Time `json:"startTime"`
	Duration  string    `json:"duration"`
}

// Server provides the HTTP API for manual captures and health checks.
type Server struct {
	captureManager *capture.CaptureManager
	health         HealthChecker
	logger         *slog.Logger
	server         *http.Server
	ctx            context.Context

	mu       sync.RWMutex
	captures []CaptureEntry
}

func NewServer(port int, captureMgr *capture.CaptureManager, health HealthChecker, logger *slog.Logger) *Server {
	s := &Server{
		captureManager: captureMgr,
		health:         health,
		logger:         logger.With("component", "api-server"),
		captures:       make([]CaptureEntry, 0),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /capture", s.handleCapture)
	mux.HandleFunc("GET /captures", s.handleListCaptures)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /ready", s.handleReady)
	mux.Handle("GET /metrics", promhttp.Handler())

	s.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	return s
}

// Run starts the HTTP server. Blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	s.ctx = ctx
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
	}()

	s.logger.Info("starting API server", "addr", s.server.Addr)

	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("API server: %w", err)
	}
	return nil
}

// RecordCapture adds a completed capture to the recent list (called by the main loop).
func (s *Server) RecordCapture(result capture.CaptureResult) {
	entry := CaptureEntry{
		Trigger:   string(result.Trigger),
		Reason:    result.Reason,
		SrcIP:     result.SrcIP,
		DstIP:     result.DstIP,
		DstPort:   result.DstPort,
		FilePath:  result.FilePath,
		StartTime: result.StartTime,
		Duration:  result.Duration.String(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.captures = append(s.captures, entry)
	// Keep last 100 entries
	if len(s.captures) > 100 {
		s.captures = s.captures[len(s.captures)-100:]
	}
}

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	var body CaptureRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	srcIP, err := normalizeIP(body.SrcCIDR, "srcCIDR")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	dstIP, err := normalizeIP(body.DstCIDR, "dstCIDR")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if body.DstPort > 65535 {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("dstPort must be in [0,65535], got %d", body.DstPort))
		return
	}

	if body.Protocol == "" {
		body.Protocol = "TCP"
	} else {
		body.Protocol = strings.ToUpper(body.Protocol)
	}
	if _, ok := allowedProtocols[body.Protocol]; !ok {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("protocol must be one of TCP, UDP, ICMPv4, ICMPv6; got %q", body.Protocol))
		return
	}

	if body.DurationSeconds < 0 {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("durationSeconds must be >= 0, got %d", body.DurationSeconds))
		return
	}

	req := detector.CaptureRequest{
		Trigger:   "manual",
		Reason:    "manual trigger via API",
		SrcIP:     srcIP,
		DstIP:     dstIP,
		DstPort:   body.DstPort,
		Protocol:  body.Protocol,
		Timestamp: time.Now(),
	}

	s.captureManager.StartManualCapture(s.ctx, req, body.DurationSeconds)

	s.logger.Info("manual capture triggered",
		"src", body.SrcCIDR,
		"dst", body.DstCIDR,
		"port", body.DstPort,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "accepted",
		"message": "capture started",
	})
}

// handleListCaptures returns recent captures, newest first. Supports:
//   - limit:   max items to return (default 100, hard cap 1000)
//   - offset:  skip the N most recent entries
//   - trigger: filter by trigger type (drop, http_error, dns_failure, latency, manual)
//
// The total count (after filtering, before pagination) is returned in the
// X-Total-Count header so clients can implement their own paging UI.
func (s *Server) handleListCaptures(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit, err := parseIntParam(q.Get("limit"), defaultListLimit, 1, maxListLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, "limit: "+err.Error())
		return
	}
	offset, err := parseIntParam(q.Get("offset"), 0, 0, 1<<31-1)
	if err != nil {
		writeError(w, http.StatusBadRequest, "offset: "+err.Error())
		return
	}
	triggerFilter := q.Get("trigger")

	s.mu.RLock()
	// Copy newest-first: the slice is appended in capture order, so iterate
	// back-to-front and optionally filter by trigger.
	filtered := make([]CaptureEntry, 0, len(s.captures))
	for i := len(s.captures) - 1; i >= 0; i-- {
		e := s.captures[i]
		if triggerFilter != "" && e.Trigger != triggerFilter {
			continue
		}
		filtered = append(filtered, e)
	}
	s.mu.RUnlock()

	total := len(filtered)
	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	page := filtered[start:end]

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	json.NewEncoder(w).Encode(page)
}

// handleHealth is a liveness probe: the process is alive and the HTTP server
// responds. It must not depend on upstream services, otherwise a transient
// Hubble outage would cause Kubernetes to restart the pod.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleReady is a readiness probe: returns 200 only when upstream
// dependencies (currently Hubble) are reachable. While not ready, the pod is
// removed from Service endpoints.
func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	body := map[string]any{
		"hubbleConnected": false,
	}
	if s.health != nil && s.health.HubbleConnected() {
		body["hubbleConnected"] = true
		body["status"] = "ready"
		json.NewEncoder(w).Encode(body)
		return
	}
	body["status"] = "not_ready"
	w.WriteHeader(http.StatusServiceUnavailable)
	json.NewEncoder(w).Encode(body)
}

// normalizeIP accepts either a bare IP ("10.0.1.5") or a CIDR ("10.0.1.5/32")
// and returns the IP string. An empty input is allowed (means "any"). The
// field name is included in error messages so callers see which input is bad.
func normalizeIP(input, field string) (string, error) {
	if input == "" {
		return "", nil
	}
	if strings.Contains(input, "/") {
		ip, _, err := net.ParseCIDR(input)
		if err != nil {
			return "", fmt.Errorf("%s: invalid CIDR %q: %w", field, input, err)
		}
		return ip.String(), nil
	}
	ip := net.ParseIP(input)
	if ip == nil {
		return "", fmt.Errorf("%s: invalid IP %q", field, input)
	}
	return ip.String(), nil
}

// parseIntParam parses a query-string integer with a default, a min, and a
// max. Empty string returns the default without error.
func parseIntParam(raw string, def, min, max int) (int, error) {
	if raw == "" {
		return def, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("not an integer: %q", raw)
	}
	if v < min || v > max {
		return 0, fmt.Errorf("must be in [%d,%d], got %d", min, max, v)
	}
	return v, nil
}

// writeError writes a JSON error body with the given HTTP status. Matches
// the JSON content-type of the success path so clients can always parse
// the body.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
