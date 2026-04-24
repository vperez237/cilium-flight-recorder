package detector

import (
	"fmt"
	"math"
	"sort"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/vperez237/cilium-flight-recorder/pkg/metrics"
)

// checkLatency fires when the per-(src→dst) P99 latency exceeds the
// configured threshold. Unlike the rate-mode triggers, latency always
// uses a fixed-size sliding window of samples (no "immediate" alternative).
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

	// Nearest-rank percentile: idx = ceil(n * p/100) - 1, clamped to [0,n-1].
	idx := int(math.Ceil(float64(n)*p/100.0)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}
