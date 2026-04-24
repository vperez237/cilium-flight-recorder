package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/vperez237/cilium-flight-recorder/pkg/capture"
	"github.com/vperez237/cilium-flight-recorder/pkg/detector"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

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
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	if body.Protocol == "" {
		body.Protocol = "TCP"
	}

	req := detector.CaptureRequest{
		Trigger:   "manual",
		Reason:    "manual trigger via API",
		SrcIP:     stripCIDR(body.SrcCIDR),
		DstIP:     stripCIDR(body.DstCIDR),
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

func (s *Server) handleListCaptures(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	entries := make([]CaptureEntry, len(s.captures))
	copy(entries, s.captures)
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
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

// stripCIDR removes the /prefix from a CIDR string to get just the IP.
func stripCIDR(cidr string) string {
	for i := 0; i < len(cidr); i++ {
		if cidr[i] == '/' {
			return cidr[:i]
		}
	}
	return cidr
}
