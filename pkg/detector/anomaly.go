package detector

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/vperez237/cilium-flight-recorder/pkg/config"
	"github.com/vperez237/cilium-flight-recorder/pkg/metrics"
	"github.com/vperez237/cilium-flight-recorder/pkg/watcher"
)

type TriggerType string

const (
	TriggerHTTPError  TriggerType = "http_error"
	TriggerDrop       TriggerType = "drop"
	TriggerDNSFailure TriggerType = "dns_failure"
	TriggerLatency    TriggerType = "latency"
)

// CaptureRequest describes what the capture manager should record.
type CaptureRequest struct {
	Trigger   TriggerType
	Reason    string
	SrcIP     string
	DstIP     string
	DstPort   uint32
	Protocol  string
	Timestamp time.Time
}

// AnomalyDetector evaluates Hubble flow events against configurable rules.
// The per-trigger logic lives in trigger_*.go files; this file contains the
// orchestration: lifecycle, dispatch, cooldown, emit, and the janitor.
type AnomalyDetector struct {
	cfg             config.TriggersConfig
	cooldown        time.Duration
	maxKeys         int
	idleTTL         time.Duration
	janitorInterval time.Duration
	captureCh       chan CaptureRequest
	logger          *slog.Logger

	mu          sync.Mutex
	lastCapture map[string]time.Time
	latencies   map[string]*slidingWindow

	// Rate-based windows (lazily initialized per key).
	httpRates map[string]*rateWindow
	dropRates map[string]*rateWindow
	dnsRates  map[string]*rateWindow
}

func NewAnomalyDetector(triggersCfg config.TriggersConfig, cooldownSeconds int, detectorCfg config.DetectorConfig, logger *slog.Logger) *AnomalyDetector {
	return &AnomalyDetector{
		cfg:             triggersCfg,
		cooldown:        time.Duration(cooldownSeconds) * time.Second,
		maxKeys:         detectorCfg.MaxTrackedKeys,
		idleTTL:         time.Duration(detectorCfg.IdleEvictAfterSeconds) * time.Second,
		janitorInterval: time.Duration(detectorCfg.JanitorIntervalSeconds) * time.Second,
		captureCh:       make(chan CaptureRequest, 256),
		logger:          logger.With("component", "anomaly-detector"),
		lastCapture:     make(map[string]time.Time),
		latencies:       make(map[string]*slidingWindow),
		httpRates:       make(map[string]*rateWindow),
		dropRates:       make(map[string]*rateWindow),
		dnsRates:        make(map[string]*rateWindow),
	}
}

// Captures returns a read-only channel of capture requests.
func (d *AnomalyDetector) Captures() <-chan CaptureRequest {
	return d.captureCh
}

// Run consumes flow events and emits capture requests when anomalies are detected.
// A periodic janitor evicts idle per-tuple bookkeeping entries to keep memory bounded.
func (d *AnomalyDetector) Run(ctx context.Context, flows <-chan watcher.FlowEvent) error {
	defer close(d.captureCh)

	ticker := time.NewTicker(d.janitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-flows:
			if !ok {
				return nil
			}
			d.evaluate(event)
		case <-ticker.C:
			d.sweepIdle()
		}
	}
}

// evaluate dispatches a flow to every enabled trigger. To add a new trigger:
// implement a check*() method in a trigger_*.go file, add a TriggerType
// constant, add its config to config.TriggersConfig, and add a line here.
func (d *AnomalyDetector) evaluate(event watcher.FlowEvent) {
	flow := event.Flow
	if flow == nil {
		return
	}
	metrics.FlowsProcessed.Inc()

	if d.cfg.Drops.Enabled {
		d.checkDrop(flow, event.Timestamp)
	}
	if d.cfg.HTTPErrors.Enabled {
		d.checkHTTPError(flow, event.Timestamp)
	}
	if d.cfg.DNSFailures.Enabled {
		d.checkDNSFailure(flow, event.Timestamp)
	}
	if d.cfg.Latency.Enabled {
		d.checkLatency(flow, event.Timestamp)
	}
}

func (d *AnomalyDetector) getOrCreateRateWindow(m map[string]*rateWindow, key string, dur time.Duration) *rateWindow {
	d.mu.Lock()
	defer d.mu.Unlock()
	rw, ok := m[key]
	if !ok {
		rw = newRateWindow(dur)
		m[key] = rw
	}
	return rw
}

// emit publishes a capture request unless the same (trigger, src, dst, port,
// proto) tuple has fired within the cooldown. Drops if the capture channel
// is full (tracked by metrics.CaptureRequestsDropped).
func (d *AnomalyDetector) emit(req CaptureRequest) {
	key := fmt.Sprintf("%s:%s:%s:%d:%s", req.Trigger, req.SrcIP, req.DstIP, req.DstPort, req.Protocol)

	d.mu.Lock()
	last, exists := d.lastCapture[key]
	if exists && time.Since(last) < d.cooldown {
		d.mu.Unlock()
		return
	}
	d.lastCapture[key] = time.Now()
	d.mu.Unlock()

	d.logger.Info("anomaly detected",
		"trigger", req.Trigger,
		"reason", req.Reason,
		"src", req.SrcIP,
		"dst", req.DstIP,
	)

	metrics.RecordTriggerFired(string(req.Trigger))

	select {
	case d.captureCh <- req:
	default:
		metrics.CaptureRequestsDropped.WithLabelValues(string(req.Trigger)).Inc()
		d.logger.Warn("capture channel full, dropping request")
	}
}

// sweepIdle evicts per-tuple bookkeeping entries that have been idle longer
// than idleTTL and enforces the maxKeys cap on each map. Exports the
// resulting sizes to Prometheus.
func (d *AnomalyDetector) sweepIdle() {
	now := time.Now()
	cutoff := now.Add(-d.idleTTL)

	d.mu.Lock()
	defer d.mu.Unlock()

	evictRateMap := func(name string, m map[string]*rateWindow) {
		for k, rw := range m {
			seen := rw.IdleSince()
			if seen.IsZero() || seen.Before(cutoff) {
				delete(m, k)
				metrics.KeysEvicted.WithLabelValues(name, "idle").Inc()
			}
		}
		d.capMap(name, m)
		metrics.TrackedKeys.WithLabelValues(name).Set(float64(len(m)))
	}

	evictRateMap("http_rates", d.httpRates)
	evictRateMap("drop_rates", d.dropRates)
	evictRateMap("dns_rates", d.dnsRates)

	// Latency windows — evict by their internal lastSeen.
	for k, sw := range d.latencies {
		if sw.lastSeen.IsZero() || sw.lastSeen.Before(cutoff) {
			delete(d.latencies, k)
			metrics.KeysEvicted.WithLabelValues("latencies", "idle").Inc()
		}
	}
	d.capLatencies()
	metrics.TrackedKeys.WithLabelValues("latencies").Set(float64(len(d.latencies)))

	// Cooldown map — an entry older than the cooldown window can never
	// suppress another capture, so it is safe to drop.
	cooldownCutoff := now.Add(-d.cooldown)
	for k, t := range d.lastCapture {
		if t.Before(cooldownCutoff) {
			delete(d.lastCapture, k)
			metrics.KeysEvicted.WithLabelValues("last_capture", "idle").Inc()
		}
	}
	metrics.TrackedKeys.WithLabelValues("last_capture").Set(float64(len(d.lastCapture)))
}

// capMap removes the oldest (by IdleSince) entries when m exceeds maxKeys.
func (d *AnomalyDetector) capMap(name string, m map[string]*rateWindow) {
	if len(m) <= d.maxKeys {
		return
	}
	type kv struct {
		k string
		t time.Time
	}
	entries := make([]kv, 0, len(m))
	for k, rw := range m {
		entries = append(entries, kv{k, rw.IdleSince()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].t.Before(entries[j].t) })
	over := len(m) - d.maxKeys
	for i := 0; i < over; i++ {
		delete(m, entries[i].k)
		metrics.KeysEvicted.WithLabelValues(name, "capacity").Inc()
	}
}

// capLatencies is the latency-map equivalent of capMap.
func (d *AnomalyDetector) capLatencies() {
	if len(d.latencies) <= d.maxKeys {
		return
	}
	type kv struct {
		k string
		t time.Time
	}
	entries := make([]kv, 0, len(d.latencies))
	for k, sw := range d.latencies {
		entries = append(entries, kv{k, sw.lastSeen})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].t.Before(entries[j].t) })
	over := len(d.latencies) - d.maxKeys
	for i := 0; i < over; i++ {
		delete(d.latencies, entries[i].k)
		metrics.KeysEvicted.WithLabelValues("latencies", "capacity").Inc()
	}
}
