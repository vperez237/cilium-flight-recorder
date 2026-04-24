package detector

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
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

// sweepIdle evicts per-tuple bookkeeping entries that have been idle longer
// than idleTTL and enforces the maxKeys cap on each map. It exports the
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

func (d *AnomalyDetector) checkDrop(flow *flowpb.Flow, ts time.Time) {
	if flow.GetVerdict() != flowpb.Verdict_DROPPED {
		return
	}

	dstIP := destinationIP(flow)
	dstPort := extractDstPort(flow)
	proto := extractProtocol(flow)

	metrics.AnomaliesDetected.WithLabelValues(string(TriggerDrop)).Inc()

	if d.cfg.Drops.Mode == config.ModeRate {
		key := fmt.Sprintf("drop:%s:%d", dstIP, dstPort)
		rw := d.getOrCreateRateWindow(d.dropRates, key, time.Duration(d.cfg.Drops.WindowSeconds)*time.Second)
		rw.Add(true)
		count := rw.ErrorCount()
		if count < d.cfg.Drops.MinDrops {
			return
		}
		req := CaptureRequest{
			Trigger:   TriggerDrop,
			Reason:    fmt.Sprintf("%d drops to %s:%d in last %ds", count, dstIP, dstPort, d.cfg.Drops.WindowSeconds),
			DstIP:     dstIP,
			DstPort:   dstPort,
			Protocol:  proto,
			Timestamp: ts,
		}
		d.emit(req)
		return
	}

	req := CaptureRequest{
		Trigger:   TriggerDrop,
		Reason:    fmt.Sprintf("packet dropped: %s", flow.GetDropReasonDesc().String()),
		SrcIP:     sourceIP(flow),
		DstIP:     dstIP,
		DstPort:   dstPort,
		Protocol:  proto,
		Timestamp: ts,
	}
	d.emit(req)
}

func (d *AnomalyDetector) checkHTTPError(flow *flowpb.Flow, ts time.Time) {
	l7 := flow.GetL7()
	if l7 == nil {
		return
	}
	http := l7.GetHttp()
	if http == nil {
		return
	}

	code := int(http.GetCode())
	if code == 0 {
		return
	}
	isError := d.isHTTPErrorCode(code)

	dstIP := destinationIP(flow)
	dstPort := extractDstPort(flow)

	if d.cfg.HTTPErrors.Mode == config.ModeRate {
		key := fmt.Sprintf("http:%s:%d", dstIP, dstPort)
		rw := d.getOrCreateRateWindow(d.httpRates, key, time.Duration(d.cfg.HTTPErrors.WindowSeconds)*time.Second)
		rw.Add(isError)
		total, errors, rate := rw.Stats()
		metrics.RateWindowErrors.WithLabelValues(string(TriggerHTTPError)).Set(rate)
		if total < d.cfg.HTTPErrors.MinEvents {
			return
		}
		if rate < d.cfg.HTTPErrors.RateThreshold {
			return
		}
		metrics.AnomaliesDetected.WithLabelValues(string(TriggerHTTPError)).Inc()
		req := CaptureRequest{
			Trigger: TriggerHTTPError,
			Reason: fmt.Sprintf("HTTP error rate %.1f%% (%d/%d) to %s:%d exceeds %.1f%% over %ds",
				rate*100, errors, total, dstIP, dstPort,
				d.cfg.HTTPErrors.RateThreshold*100, d.cfg.HTTPErrors.WindowSeconds),
			DstIP:     dstIP,
			DstPort:   dstPort,
			Protocol:  "TCP",
			Timestamp: ts,
		}
		d.emit(req)
		return
	}

	if !isError {
		return
	}

	metrics.AnomaliesDetected.WithLabelValues(string(TriggerHTTPError)).Inc()
	req := CaptureRequest{
		Trigger:   TriggerHTTPError,
		Reason:    fmt.Sprintf("HTTP %d on %s %s", code, http.GetMethod(), http.GetUrl()),
		SrcIP:     sourceIP(flow),
		DstIP:     dstIP,
		DstPort:   dstPort,
		Protocol:  "TCP",
		Timestamp: ts,
	}
	d.emit(req)
}

func (d *AnomalyDetector) checkDNSFailure(flow *flowpb.Flow, ts time.Time) {
	l7 := flow.GetL7()
	if l7 == nil {
		return
	}
	dns := l7.GetDns()
	if dns == nil {
		return
	}

	rcode := rcodeToString(int(dns.GetRcode()))
	isFailure := d.isDNSFailureRCode(rcode)

	srcIPStr := sourceIP(flow)

	if d.cfg.DNSFailures.Mode == config.ModeRate {
		key := fmt.Sprintf("dns:%s", srcIPStr)
		rw := d.getOrCreateRateWindow(d.dnsRates, key, time.Duration(d.cfg.DNSFailures.WindowSeconds)*time.Second)
		rw.Add(isFailure)
		total, errors, rate := rw.Stats()
		metrics.RateWindowErrors.WithLabelValues(string(TriggerDNSFailure)).Set(rate)
		if total < d.cfg.DNSFailures.MinEvents {
			return
		}
		if rate < d.cfg.DNSFailures.RateThreshold {
			return
		}
		metrics.AnomaliesDetected.WithLabelValues(string(TriggerDNSFailure)).Inc()
		req := CaptureRequest{
			Trigger: TriggerDNSFailure,
			Reason: fmt.Sprintf("DNS failure rate %.1f%% (%d/%d) from %s exceeds %.1f%% over %ds",
				rate*100, errors, total, srcIPStr,
				d.cfg.DNSFailures.RateThreshold*100, d.cfg.DNSFailures.WindowSeconds),
			SrcIP:     srcIPStr,
			DstPort:   53,
			Protocol:  "UDP",
			Timestamp: ts,
		}
		d.emit(req)
		return
	}

	if !isFailure {
		return
	}

	metrics.AnomaliesDetected.WithLabelValues(string(TriggerDNSFailure)).Inc()
	req := CaptureRequest{
		Trigger:   TriggerDNSFailure,
		Reason:    fmt.Sprintf("DNS %s for query %s", rcode, dns.GetQuery()),
		SrcIP:     srcIPStr,
		DstIP:     destinationIP(flow),
		DstPort:   53,
		Protocol:  "UDP",
		Timestamp: ts,
	}
	d.emit(req)
}

func (d *AnomalyDetector) checkLatency(flow *flowpb.Flow, ts time.Time) {
	l7 := flow.GetL7()
	if l7 == nil || l7.GetLatencyNs() == 0 {
		return
	}

	latencyMs := float64(l7.GetLatencyNs()) / 1e6
	key := fmt.Sprintf("%s->%s", sourceIP(flow), destinationIP(flow))

	d.mu.Lock()
	sw, ok := d.latencies[key]
	if !ok {
		sw = newSlidingWindow(d.cfg.Latency.WindowSize)
		d.latencies[key] = sw
	}
	sw.Add(latencyMs)
	p99 := sw.Percentile(99)
	d.mu.Unlock()

	if p99 < float64(d.cfg.Latency.ThresholdMs) {
		return
	}

	metrics.AnomaliesDetected.WithLabelValues(string(TriggerLatency)).Inc()
	req := CaptureRequest{
		Trigger:   TriggerLatency,
		Reason:    fmt.Sprintf("P99 latency %.0fms exceeds %dms threshold", p99, d.cfg.Latency.ThresholdMs),
		SrcIP:     sourceIP(flow),
		DstIP:     destinationIP(flow),
		DstPort:   extractDstPort(flow),
		Protocol:  extractProtocol(flow),
		Timestamp: ts,
	}
	d.emit(req)
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

func (d *AnomalyDetector) isHTTPErrorCode(code int) bool {
	for _, c := range d.cfg.HTTPErrors.StatusCodes {
		if c == code {
			return true
		}
	}
	return false
}

func (d *AnomalyDetector) isDNSFailureRCode(rcode string) bool {
	for _, r := range d.cfg.DNSFailures.RCodes {
		if r == rcode {
			return true
		}
	}
	return false
}

func extractIP(ep *flowpb.Endpoint) string {
	if ep == nil {
		return ""
	}
	return fmt.Sprintf("%d", ep.GetID())
}

func sourceIP(flow *flowpb.Flow) string {
	if ip := flow.GetIP(); ip != nil {
		return ip.GetSource()
	}
	return extractIP(flow.GetSource())
}

func destinationIP(flow *flowpb.Flow) string {
	if ip := flow.GetIP(); ip != nil {
		return ip.GetDestination()
	}
	return extractIP(flow.GetDestination())
}

func extractDstPort(flow *flowpb.Flow) uint32 {
	l4 := flow.GetL4()
	if l4 == nil {
		return 0
	}
	if tcp := l4.GetTCP(); tcp != nil {
		return tcp.GetDestinationPort()
	}
	if udp := l4.GetUDP(); udp != nil {
		return udp.GetDestinationPort()
	}
	return 0
}

func extractProtocol(flow *flowpb.Flow) string {
	l4 := flow.GetL4()
	if l4 == nil {
		return "TCP"
	}
	if l4.GetTCP() != nil {
		return "TCP"
	}
	if l4.GetUDP() != nil {
		return "UDP"
	}
	if l4.GetICMPv4() != nil {
		return "ICMPv4"
	}
	if l4.GetICMPv6() != nil {
		return "ICMPv6"
	}
	return "TCP"
}

var rcodeNames = map[int]string{
	0: "NOERROR",
	1: "FORMERR",
	2: "SERVFAIL",
	3: "NXDOMAIN",
	4: "NOTIMP",
	5: "REFUSED",
}

func rcodeToString(rcode int) string {
	if name, ok := rcodeNames[rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE_%d", rcode)
}

// slidingWindow tracks the last N values for percentile computation.
type slidingWindow struct {
	values   []float64
	size     int
	pos      int
	full     bool
	lastSeen time.Time
}

func newSlidingWindow(size int) *slidingWindow {
	return &slidingWindow{
		values: make([]float64, size),
		size:   size,
	}
}

func (w *slidingWindow) Add(v float64) {
	w.values[w.pos] = v
	w.pos++
	if w.pos >= w.size {
		w.pos = 0
		w.full = true
	}
	w.lastSeen = time.Now()
}

func (w *slidingWindow) Percentile(p float64) float64 {
	n := w.size
	if !w.full {
		n = w.pos
	}
	if n == 0 {
		return 0
	}

	sorted := make([]float64, n)
	copy(sorted, w.values[:n])
	sort.Float64s(sorted)

	idx := int(float64(n-1) * p / 100)
	return sorted[idx]
}
