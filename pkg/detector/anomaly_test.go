package detector

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/vperez237/cilium-flight-recorder/pkg/config"
	"github.com/vperez237/cilium-flight-recorder/pkg/watcher"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func defaultDetectorConfig() config.DetectorConfig {
	return config.DetectorConfig{
		MaxTrackedKeys:         1000,
		IdleEvictAfterSeconds:  600,
		JanitorIntervalSeconds: 60,
	}
}

func defaultTriggersConfig() config.TriggersConfig {
	return config.TriggersConfig{
		HTTPErrors: config.HTTPErrorsConfig{
			Enabled:     true,
			StatusCodes: []int{500, 502, 503, 504},
		},
		Drops: config.DropsConfig{
			Enabled: true,
		},
		DNSFailures: config.DNSFailuresConfig{
			Enabled: true,
			RCodes:  []string{"NXDOMAIN", "SERVFAIL", "REFUSED"},
		},
		Latency: config.LatencyConfig{
			Enabled:     true,
			ThresholdMs: 2000,
			WindowSize:  10,
		},
	}
}

func drainCaptures(ch <-chan CaptureRequest, timeout time.Duration) []CaptureRequest {
	var results []CaptureRequest
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case req, ok := <-ch:
			if !ok {
				return results
			}
			results = append(results, req)
		case <-timer.C:
			return results
		}
	}
}

func TestDetectsDroppedPackets(t *testing.T) {
	d := NewAnomalyDetector(defaultTriggersConfig(), 0, defaultDetectorConfig(), testLogger())

	flowCh := make(chan watcher.FlowEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go d.Run(ctx, flowCh)

	flowCh <- watcher.FlowEvent{
		Flow: &flowpb.Flow{
			Verdict:        flowpb.Verdict_DROPPED,
			DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
			Time:           timestamppb.Now(),
			IP: &flowpb.IP{
				Source:      "10.0.1.5",
				Destination: "10.0.2.10",
			},
			L4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_TCP{
					TCP: &flowpb.TCP{DestinationPort: 8080},
				},
			},
		},
		Timestamp: time.Now(),
	}

	captures := drainCaptures(d.Captures(), 200*time.Millisecond)
	if len(captures) == 0 {
		t.Fatal("expected a capture request for dropped packet, got none")
	}
	if captures[0].Trigger != TriggerDrop {
		t.Errorf("expected trigger %s, got %s", TriggerDrop, captures[0].Trigger)
	}
}

func TestDetectsHTTP5xx(t *testing.T) {
	d := NewAnomalyDetector(defaultTriggersConfig(), 0, defaultDetectorConfig(), testLogger())

	flowCh := make(chan watcher.FlowEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go d.Run(ctx, flowCh)

	flowCh <- watcher.FlowEvent{
		Flow: &flowpb.Flow{
			Verdict: flowpb.Verdict_FORWARDED,
			Time:    timestamppb.Now(),
			IP: &flowpb.IP{
				Source:      "10.0.1.5",
				Destination: "10.0.2.10",
			},
			L4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_TCP{
					TCP: &flowpb.TCP{DestinationPort: 443},
				},
			},
			L7: &flowpb.Layer7{
				Record: &flowpb.Layer7_Http{
					Http: &flowpb.HTTP{
						Code:   503,
						Method: "GET",
						Url:    "/api/health",
					},
				},
			},
		},
		Timestamp: time.Now(),
	}

	captures := drainCaptures(d.Captures(), 200*time.Millisecond)
	if len(captures) == 0 {
		t.Fatal("expected a capture request for HTTP 503, got none")
	}
	if captures[0].Trigger != TriggerHTTPError {
		t.Errorf("expected trigger %s, got %s", TriggerHTTPError, captures[0].Trigger)
	}
}

func TestIgnoresHTTP200(t *testing.T) {
	d := NewAnomalyDetector(defaultTriggersConfig(), 0, defaultDetectorConfig(), testLogger())

	flowCh := make(chan watcher.FlowEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go d.Run(ctx, flowCh)

	flowCh <- watcher.FlowEvent{
		Flow: &flowpb.Flow{
			Verdict: flowpb.Verdict_FORWARDED,
			Time:    timestamppb.Now(),
			L7: &flowpb.Layer7{
				Record: &flowpb.Layer7_Http{
					Http: &flowpb.HTTP{
						Code:   200,
						Method: "GET",
						Url:    "/api/health",
					},
				},
			},
		},
		Timestamp: time.Now(),
	}

	captures := drainCaptures(d.Captures(), 200*time.Millisecond)
	if len(captures) != 0 {
		t.Fatalf("expected no capture request for HTTP 200, got %d", len(captures))
	}
}

func TestDetectsDNSFailure(t *testing.T) {
	d := NewAnomalyDetector(defaultTriggersConfig(), 0, defaultDetectorConfig(), testLogger())

	flowCh := make(chan watcher.FlowEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go d.Run(ctx, flowCh)

	flowCh <- watcher.FlowEvent{
		Flow: &flowpb.Flow{
			Verdict: flowpb.Verdict_FORWARDED,
			Time:    timestamppb.Now(),
			IP: &flowpb.IP{
				Source:      "10.0.1.5",
				Destination: "10.0.0.2",
			},
			L4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_UDP{
					UDP: &flowpb.UDP{DestinationPort: 53},
				},
			},
			L7: &flowpb.Layer7{
				Record: &flowpb.Layer7_Dns{
					Dns: &flowpb.DNS{
						Query: "nonexistent.example.com",
						Rcode: 3, // NXDOMAIN
					},
				},
			},
		},
		Timestamp: time.Now(),
	}

	captures := drainCaptures(d.Captures(), 200*time.Millisecond)
	if len(captures) == 0 {
		t.Fatal("expected a capture request for DNS NXDOMAIN, got none")
	}
	if captures[0].Trigger != TriggerDNSFailure {
		t.Errorf("expected trigger %s, got %s", TriggerDNSFailure, captures[0].Trigger)
	}
}

func TestCooldownPreventsRepeatedCaptures(t *testing.T) {
	d := NewAnomalyDetector(defaultTriggersConfig(), 60, defaultDetectorConfig(), testLogger())

	flowCh := make(chan watcher.FlowEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go d.Run(ctx, flowCh)

	dropFlow := watcher.FlowEvent{
		Flow: &flowpb.Flow{
			Verdict:        flowpb.Verdict_DROPPED,
			DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
			Time:           timestamppb.Now(),
			IP: &flowpb.IP{
				Source:      "10.0.1.5",
				Destination: "10.0.2.10",
			},
			L4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_TCP{
					TCP: &flowpb.TCP{DestinationPort: 8080},
				},
			},
		},
		Timestamp: time.Now(),
	}

	// Send the same drop flow twice
	flowCh <- dropFlow
	flowCh <- dropFlow
	flowCh <- dropFlow

	captures := drainCaptures(d.Captures(), 300*time.Millisecond)
	if len(captures) != 1 {
		t.Fatalf("expected exactly 1 capture due to cooldown, got %d", len(captures))
	}
}

func TestSlidingWindowPercentile(t *testing.T) {
	sw := newSlidingWindow(10)

	for i := 1; i <= 10; i++ {
		sw.Add(float64(i * 100))
	}

	p99 := sw.Percentile(99)
	if p99 != 1000 {
		t.Errorf("expected P99 of 1000, got %.0f", p99)
	}

	p50 := sw.Percentile(50)
	if p50 != 500 {
		t.Errorf("expected P50 near 500, got %.0f", p50)
	}
}

func TestSlidingWindowWraparound(t *testing.T) {
	sw := newSlidingWindow(5)

	// Fill with low values
	for i := 0; i < 5; i++ {
		sw.Add(100)
	}

	// Overwrite with high values
	for i := 0; i < 5; i++ {
		sw.Add(5000)
	}

	p99 := sw.Percentile(99)
	if p99 != 5000 {
		t.Errorf("expected P99 of 5000 after wraparound, got %.0f", p99)
	}
}

func TestJanitorEvictsIdleRateWindows(t *testing.T) {
	d := NewAnomalyDetector(defaultTriggersConfig(), 60, defaultDetectorConfig(), testLogger())
	d.idleTTL = 10 * time.Millisecond

	// Populate a rate window and mark it idle by rewinding its lastSeen.
	rw := newRateWindow(time.Second)
	rw.Add(true)
	rw.lastSeen = time.Now().Add(-time.Hour)
	d.httpRates["stale"] = rw

	// A freshly-touched entry should survive.
	fresh := newRateWindow(time.Second)
	fresh.Add(false)
	d.httpRates["fresh"] = fresh

	d.sweepIdle()

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.httpRates["stale"]; ok {
		t.Error("expected idle entry to be evicted")
	}
	if _, ok := d.httpRates["fresh"]; !ok {
		t.Error("expected fresh entry to survive")
	}
}

func TestJanitorEvictsStaleLatencyWindows(t *testing.T) {
	d := NewAnomalyDetector(defaultTriggersConfig(), 60, defaultDetectorConfig(), testLogger())
	d.idleTTL = 10 * time.Millisecond

	sw := newSlidingWindow(10)
	sw.Add(100)
	sw.lastSeen = time.Now().Add(-time.Hour)
	d.latencies["stale"] = sw

	d.sweepIdle()

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.latencies["stale"]; ok {
		t.Error("expected stale latency window to be evicted")
	}
}

func TestJanitorEvictsExpiredCooldownEntries(t *testing.T) {
	d := NewAnomalyDetector(defaultTriggersConfig(), 5, defaultDetectorConfig(), testLogger())
	d.lastCapture["old"] = time.Now().Add(-time.Hour)
	d.lastCapture["new"] = time.Now()

	d.sweepIdle()

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.lastCapture["old"]; ok {
		t.Error("expected expired cooldown entry to be evicted")
	}
	if _, ok := d.lastCapture["new"]; !ok {
		t.Error("expected recent cooldown entry to survive")
	}
}

func TestJanitorEnforcesCapacity(t *testing.T) {
	cfg := defaultDetectorConfig()
	cfg.MaxTrackedKeys = 3
	d := NewAnomalyDetector(defaultTriggersConfig(), 60, cfg, testLogger())
	// Set idleTTL very high so only capacity triggers eviction.
	d.idleTTL = time.Hour

	base := time.Now().Add(-time.Minute)
	for i := 0; i < 6; i++ {
		rw := newRateWindow(time.Second)
		rw.Add(true)
		rw.lastSeen = base.Add(time.Duration(i) * time.Second)
		d.httpRates[keyN(i)] = rw
	}

	d.sweepIdle()

	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.httpRates) != 3 {
		t.Fatalf("expected capacity to cap map at 3, got %d", len(d.httpRates))
	}
	// Oldest three (0, 1, 2) should be evicted; newest three (3, 4, 5) retained.
	for _, i := range []int{0, 1, 2} {
		if _, ok := d.httpRates[keyN(i)]; ok {
			t.Errorf("expected key %s (oldest) to be evicted", keyN(i))
		}
	}
	for _, i := range []int{3, 4, 5} {
		if _, ok := d.httpRates[keyN(i)]; !ok {
			t.Errorf("expected key %s (newest) to survive", keyN(i))
		}
	}
}

func keyN(i int) string {
	return "k" + string(rune('0'+i))
}

func TestDisabledTriggers(t *testing.T) {
	cfg := defaultTriggersConfig()
	cfg.Drops.Enabled = false
	cfg.HTTPErrors.Enabled = false
	cfg.DNSFailures.Enabled = false
	cfg.Latency.Enabled = false

	d := NewAnomalyDetector(cfg, 0, defaultDetectorConfig(), testLogger())

	flowCh := make(chan watcher.FlowEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go d.Run(ctx, flowCh)

	flowCh <- watcher.FlowEvent{
		Flow: &flowpb.Flow{
			Verdict:        flowpb.Verdict_DROPPED,
			DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
			Time:           timestamppb.Now(),
		},
		Timestamp: time.Now(),
	}

	captures := drainCaptures(d.Captures(), 200*time.Millisecond)
	if len(captures) != 0 {
		t.Fatalf("expected no captures when all triggers disabled, got %d", len(captures))
	}
}
