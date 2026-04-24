package capture

import (
	"errors"
	"testing"
	"time"
)

func TestCircuitBreakerClosedToOpen(t *testing.T) {
	b := newCircuitBreaker(3, time.Second)
	boom := errors.New("socket unreachable")

	// Two failures: still closed.
	for i := 0; i < 2; i++ {
		if err := b.allow(); err != nil {
			t.Fatalf("attempt %d: allow() returned %v, want nil", i, err)
		}
		b.report(boom)
	}

	// Third failure: hit threshold, breaker opens on this report.
	if err := b.allow(); err != nil {
		t.Fatalf("attempt 3: allow() returned %v, want nil", err)
	}
	b.report(boom)

	// Next call is short-circuited.
	if err := b.allow(); !errors.Is(err, ErrCiliumUnavailable) {
		t.Fatalf("expected ErrCiliumUnavailable after threshold, got %v", err)
	}
}

func TestCircuitBreakerResetsOnSuccess(t *testing.T) {
	b := newCircuitBreaker(3, time.Second)
	boom := errors.New("boom")

	_ = b.allow()
	b.report(boom)
	_ = b.allow()
	b.report(boom)

	// A single success clears the consecutive-failure counter.
	_ = b.allow()
	b.report(nil)

	// Two more failures should not trip (counter was reset to 0).
	_ = b.allow()
	b.report(boom)
	_ = b.allow()
	b.report(boom)

	if err := b.allow(); err != nil {
		t.Fatalf("breaker tripped too early after reset: %v", err)
	}
}

func TestCircuitBreakerHalfOpenProbeSuccessCloses(t *testing.T) {
	b := newCircuitBreaker(1, 20*time.Millisecond) // trip on first failure
	boom := errors.New("boom")

	_ = b.allow()
	b.report(boom) // opens

	// Immediately after: open.
	if err := b.allow(); !errors.Is(err, ErrCiliumUnavailable) {
		t.Fatalf("want open, got %v", err)
	}

	// After cooldown: half-open allows a probe.
	time.Sleep(30 * time.Millisecond)
	if err := b.allow(); err != nil {
		t.Fatalf("post-cooldown probe should be allowed, got %v", err)
	}

	// A concurrent call during the probe is rejected.
	if err := b.allow(); !errors.Is(err, ErrCiliumUnavailable) {
		t.Fatalf("concurrent call during probe should short-circuit, got %v", err)
	}

	// Probe succeeds → breaker closes → traffic flows normally again.
	b.report(nil)
	if err := b.allow(); err != nil {
		t.Fatalf("breaker should be closed after successful probe, got %v", err)
	}
}

func TestCircuitBreakerHalfOpenProbeFailureReopens(t *testing.T) {
	b := newCircuitBreaker(1, 20*time.Millisecond)
	boom := errors.New("boom")

	_ = b.allow()
	b.report(boom) // opens

	time.Sleep(30 * time.Millisecond)
	if err := b.allow(); err != nil {
		t.Fatalf("probe should be allowed, got %v", err)
	}
	b.report(boom) // probe fails → back to open for a fresh cooldown

	if err := b.allow(); !errors.Is(err, ErrCiliumUnavailable) {
		t.Fatalf("breaker should be re-opened after probe failure, got %v", err)
	}
}
