package storage

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestSentinelErrorsChain(t *testing.T) {
	// Transient errors wrapped by Upload() as terminal after retries should
	// be identifiable as BOTH via errors.Is — callers can filter at either
	// granularity.
	inner := errors.New("network timeout")
	transient := fmt.Errorf("%w: %w", ErrS3Transient, inner)
	terminal := fmt.Errorf("%w: after 5 attempts: %w", ErrS3Terminal, transient)

	if !errors.Is(terminal, ErrS3Terminal) {
		t.Error("final error should be ErrS3Terminal")
	}
	if !errors.Is(terminal, ErrS3Transient) {
		t.Error("final error should still carry ErrS3Transient in its chain")
	}
	if !errors.Is(terminal, inner) {
		t.Error("final error should still wrap the innermost cause")
	}
	// A pure transient (not yet wrapped as terminal) should not match terminal.
	if errors.Is(transient, ErrS3Terminal) {
		t.Error("transient-only error should not match ErrS3Terminal")
	}
}

func TestBackoffFor(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 2 * time.Second

	cases := []struct {
		attempt int
		min     time.Duration // lower bound after jitter
		max     time.Duration // upper bound after jitter
	}{
		{1, 80 * time.Millisecond, 120 * time.Millisecond},
		{2, 160 * time.Millisecond, 240 * time.Millisecond},
		{3, 320 * time.Millisecond, 480 * time.Millisecond},
		{4, 640 * time.Millisecond, 960 * time.Millisecond},
		// attempt 5 -> 1600ms base; jittered range [1280ms, 1920ms].
		{5, 1280 * time.Millisecond, 1920 * time.Millisecond},
		// attempt 6 -> capped at max (2s); jittered range [1600ms, 2400ms].
		{6, 1600 * time.Millisecond, 2400 * time.Millisecond},
		// attempt 10 — still capped.
		{10, 1600 * time.Millisecond, 2400 * time.Millisecond},
	}

	for _, tc := range cases {
		// Sample a few times to cover jitter.
		for i := 0; i < 10; i++ {
			got := backoffFor(tc.attempt, initial, max)
			if got < tc.min || got > tc.max {
				t.Errorf("attempt %d sample %d: got %v, want in [%v,%v]",
					tc.attempt, i, got, tc.min, tc.max)
			}
		}
	}
}
