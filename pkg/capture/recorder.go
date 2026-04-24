package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vperez237/cilium-flight-recorder/pkg/config"
	"github.com/vperez237/cilium-flight-recorder/pkg/detector"
	"github.com/vperez237/cilium-flight-recorder/pkg/metrics"
	"github.com/vperez237/cilium-flight-recorder/pkg/tracing"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// CaptureResult describes a completed PCAP capture.
type CaptureResult struct {
	FilePath  string
	Trigger   detector.TriggerType
	Reason    string
	SrcIP     string
	DstIP     string
	DstPort   uint32
	Protocol  string
	StartTime time.Time
	Duration  time.Duration
}

// CaptureManager orchestrates PCAP captures via the Cilium agent REST API.
type CaptureManager struct {
	socketPath string
	outputDir  string
	cfg        config.CaptureConfig
	resultCh   chan CaptureResult
	logger     *slog.Logger
	client     *http.Client
	breaker    *circuitBreaker

	activeCount atomic.Int32
	nextID      atomic.Int64
	mu          sync.Mutex
}

func NewCaptureManager(socketPath, outputDir string, cfg config.CaptureConfig, ciliumCfg config.CiliumConfig, logger *slog.Logger) (*CaptureManager, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}

	return &CaptureManager{
		socketPath: socketPath,
		outputDir:  outputDir,
		cfg:        cfg,
		resultCh:   make(chan CaptureResult, 64),
		logger:     logger.With("component", "capture-manager"),
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		breaker: newCircuitBreaker(
			ciliumCfg.CircuitFailureThreshold,
			time.Duration(ciliumCfg.CircuitCooldownSeconds)*time.Second,
		),
	}, nil
}

// Results returns a read-only channel of completed capture results.
func (m *CaptureManager) Results() <-chan CaptureResult {
	return m.resultCh
}

// Run consumes capture requests and manages the recording lifecycle.
func (m *CaptureManager) Run(ctx context.Context, requests <-chan detector.CaptureRequest) error {
	defer close(m.resultCh)

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case req, ok := <-requests:
			if !ok {
				return nil
			}

			if int(m.activeCount.Load()) >= m.cfg.MaxConcurrent {
				metrics.RecordCaptureFailed(string(req.Trigger), "max_concurrent_reached")
				m.logger.Warn("max concurrent captures reached, skipping",
					"active", m.activeCount.Load(),
					"max", m.cfg.MaxConcurrent,
				)
				continue
			}

			wg.Add(1)
			go func(r detector.CaptureRequest) {
				defer wg.Done()
				m.executeCapture(ctx, r)
			}(req)
		}
	}
}

// StartManualCapture triggers a capture from the HTTP API.
func (m *CaptureManager) StartManualCapture(ctx context.Context, req detector.CaptureRequest, durationSeconds int) {
	if durationSeconds <= 0 {
		durationSeconds = m.cfg.DefaultDurationSeconds
	}
	go func() {
		m.executeCaptureWithDuration(ctx, req, time.Duration(durationSeconds)*time.Second)
	}()
}

func (m *CaptureManager) executeCapture(ctx context.Context, req detector.CaptureRequest) {
	duration := time.Duration(m.cfg.DefaultDurationSeconds) * time.Second
	m.executeCaptureWithDuration(ctx, req, duration)
}

func (m *CaptureManager) executeCaptureWithDuration(ctx context.Context, req detector.CaptureRequest, duration time.Duration) {
	m.activeCount.Add(1)
	metrics.ActiveCaptures.Inc()
	defer func() {
		m.activeCount.Add(-1)
		metrics.ActiveCaptures.Dec()
	}()

	recorderID := m.nextID.Add(1)
	startTime := time.Now()
	trigger := string(req.Trigger)

	// Root span for this capture. Child spans for createRecorder /
	// stopAndCollect are started inside those methods.
	ctx, span := tracing.Tracer().Start(ctx, "capture.execute",
		trace.WithAttributes(
			attribute.String("trigger", trigger),
			attribute.String("reason", req.Reason),
			attribute.String("src_ip", req.SrcIP),
			attribute.String("dst_ip", req.DstIP),
			attribute.Int("dst_port", int(req.DstPort)),
			attribute.String("protocol", req.Protocol),
			attribute.Int64("recorder_id", recorderID),
			attribute.Float64("duration_seconds", duration.Seconds()),
		),
	)
	defer span.End()

	m.logger.Info("starting capture",
		"recorder_id", recorderID,
		"trigger", req.Trigger,
		"src", req.SrcIP,
		"dst", req.DstIP,
		"duration", duration,
	)
	metrics.RecordCaptureStarted(trigger)

	if err := m.createRecorder(ctx, recorderID, req); err != nil {
		metrics.RecordCaptureFailed(trigger, "create_recorder")
		m.logger.Error("failed to create recorder", "error", err, "recorder_id", recorderID)
		span.RecordError(err)
		span.SetStatus(codes.Error, "create recorder failed")
		return
	}

	select {
	case <-ctx.Done():
	case <-time.After(duration):
	}

	pcapPath, err := m.stopAndCollect(ctx, recorderID, req, startTime)
	if err != nil {
		metrics.RecordCaptureFailed(trigger, "stop_and_collect")
		m.logger.Error("failed to stop recorder", "error", err, "recorder_id", recorderID)
		span.RecordError(err)
		span.SetStatus(codes.Error, "stop and collect failed")
		return
	}

	elapsed := time.Since(startTime)
	metrics.RecordCaptureCompleted(trigger, elapsed.Seconds())

	result := CaptureResult{
		FilePath:  pcapPath,
		Trigger:   req.Trigger,
		Reason:    req.Reason,
		SrcIP:     req.SrcIP,
		DstIP:     req.DstIP,
		DstPort:   req.DstPort,
		Protocol:  req.Protocol,
		StartTime: startTime,
		Duration:  elapsed,
	}

	select {
	case m.resultCh <- result:
	default:
		m.logger.Warn("result channel full, dropping capture result")
	}
}

type recorderConfig struct {
	ID      int64            `json:"id"`
	Filters []recorderFilter `json:"filters"`
}

type recorderFilter struct {
	SourceCIDR string `json:"source-cidr,omitempty"`
	DestCIDR   string `json:"dest-cidr,omitempty"`
	DestPort   string `json:"dest-port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
}

func (m *CaptureManager) createRecorder(ctx context.Context, id int64, req detector.CaptureRequest) error {
	ctx, span := tracing.Tracer().Start(ctx, "cilium.createRecorder",
		trace.WithAttributes(attribute.Int64("recorder_id", id)),
	)
	defer span.End()

	filter := recorderFilter{
		Protocol: protocolToNumber(req.Protocol),
	}
	if req.SrcIP != "" {
		filter.SourceCIDR = req.SrcIP + "/32"
	}
	if req.DstIP != "" {
		filter.DestCIDR = req.DstIP + "/32"
	}
	if req.DstPort > 0 {
		filter.DestPort = fmt.Sprintf("%d", req.DstPort)
	}

	cfg := recorderConfig{
		ID:      id,
		Filters: []recorderFilter{filter},
	}

	body, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling recorder config: %w", err)
	}

	url := fmt.Sprintf("http://localhost/v1/recorder/%d", id)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if err := m.breaker.allow(); err != nil {
		return err
	}
	resp, err := m.client.Do(httpReq)
	if err != nil {
		m.breaker.report(err)
		return fmt.Errorf("creating recorder: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		// 4xx (client-side misuse) shouldn't trip the breaker; only 5xx
		// suggests the agent itself is unhealthy.
		apiErr := fmt.Errorf("cilium API returned %d: %s", resp.StatusCode, string(respBody))
		if resp.StatusCode >= 500 {
			m.breaker.report(apiErr)
		} else {
			m.breaker.report(nil)
		}
		return apiErr
	}

	m.breaker.report(nil)
	return nil
}

func (m *CaptureManager) stopAndCollect(ctx context.Context, id int64, req detector.CaptureRequest, startTime time.Time) (string, error) {
	_, span := tracing.Tracer().Start(ctx, "cilium.stopAndCollect",
		trace.WithAttributes(attribute.Int64("recorder_id", id)),
	)
	defer span.End()

	url := fmt.Sprintf("http://localhost/v1/recorder/%d", id)
	httpReq, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return "", err
	}

	if err := m.breaker.allow(); err != nil {
		return "", err
	}
	resp, err := m.client.Do(httpReq)
	if err != nil {
		m.breaker.report(err)
		return "", fmt.Errorf("stopping recorder: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		m.breaker.report(fmt.Errorf("cilium API returned %d", resp.StatusCode))
	} else {
		m.breaker.report(nil)
	}

	srcPath := filepath.Join(m.cfg.PcapSourceDir, fmt.Sprintf("%d.pcap", id))
	dstFilename := fmt.Sprintf("%s_%s_%s_%s_%d.pcap",
		startTime.UTC().Format("20060102T150405Z"),
		req.Trigger,
		sanitize(req.SrcIP),
		sanitize(req.DstIP),
		req.DstPort,
	)
	dstPath := filepath.Join(m.outputDir, dstFilename)

	if err := copyFile(srcPath, dstPath); err != nil {
		return "", fmt.Errorf("collecting PCAP: %w", err)
	}

	// Clean up the source file
	_ = os.Remove(srcPath)

	m.logger.Info("capture completed",
		"recorder_id", id,
		"file", dstPath,
		"trigger", req.Trigger,
	)

	return dstPath, nil
}

func protocolToNumber(proto string) string {
	switch proto {
	case "TCP":
		return "6"
	case "UDP":
		return "17"
	case "ICMPv4":
		return "1"
	case "ICMPv6":
		return "58"
	default:
		return "6"
	}
}

func sanitize(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}

// copyFile copies src to dst atomically: bytes land in dst+".tmp" first, get
// fsync'd, and only then does rename publish them to dst. A crash mid-write
// leaves a .tmp sibling rather than a half-written PCAP that the uploader
// would ship.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	// If anything below fails after Create, leave nothing behind.
	cleanup := func() { _ = os.Remove(tmp) }

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		cleanup()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		cleanup()
		return err
	}
	if err := out.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		cleanup()
		return err
	}
	return nil
}
