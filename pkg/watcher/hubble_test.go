package watcher

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestBackoffDurationGrowsAndCaps(t *testing.T) {
	w := NewHubbleWatcher("unused:0", 0, testLogger())

	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 1 * time.Second},
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{3, 8 * time.Second},
		{4, 16 * time.Second},
		{5, 30 * time.Second}, // capped at 30s
		{10, 30 * time.Second},
		{50, 30 * time.Second},
	}
	for _, tc := range cases {
		got := w.backoffDuration(tc.attempt)
		if got != tc.want {
			t.Errorf("backoffDuration(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

func TestConnectedDefaultsFalse(t *testing.T) {
	w := NewHubbleWatcher("unused:0", 0, testLogger())
	if w.Connected() {
		t.Error("newly constructed watcher should not report Connected()=true")
	}
}

func TestSetConnectedRoundTrip(t *testing.T) {
	w := NewHubbleWatcher("unused:0", 0, testLogger())
	w.setConnected(true)
	if !w.Connected() {
		t.Error("after setConnected(true), Connected() should be true")
	}
	w.setConnected(false)
	if w.Connected() {
		t.Error("after setConnected(false), Connected() should be false")
	}
}

// TestRunReturnsOnContextCancel verifies that Run honours context cancellation
// even while stuck in the reconnect backoff loop. We point it at an address
// that's guaranteed to fail to connect; the stream loop should keep retrying
// until ctx is cancelled, then return ctx.Err() without leaking goroutines.
func TestRunReturnsOnContextCancel(t *testing.T) {
	// 127.0.0.1:1 is almost always refused — a cheap way to make every
	// reconnect attempt fail fast.
	w := NewHubbleWatcher("127.0.0.1:1", 8, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	// Give Run time to fail its first dial and enter backoff, then cancel.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of cancel — possible leak")
	}

	// Flow channel should be closed after Run returns.
	if _, ok := <-w.Flows(); ok {
		t.Error("Flows channel not closed after Run returned")
	}
}

// TestRunStaysDisconnectedWhenEndpointUnreachable exercises the metric path:
// Connected() should remain false the entire time Run is retrying against a
// dead endpoint.
func TestRunStaysDisconnectedWhenEndpointUnreachable(t *testing.T) {
	w := NewHubbleWatcher("127.0.0.1:1", 4, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = w.Run(ctx)
		close(done)
	}()

	// Poll Connected() while Run is stuck retrying.
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		if w.Connected() {
			t.Fatal("Connected() became true against an unreachable endpoint")
		}
		time.Sleep(20 * time.Millisecond)
	}
	<-done
}
