package detector

import (
	"sync"
	"time"
)

// rateEvent records a single observation within a rolling time window.
type rateEvent struct {
	ts      time.Time
	errored bool
}

// rateWindow is a rolling time-bucket of observations used to compute
// error rates (e.g. HTTP 5xx / total HTTP responses over the last 60s).
type rateWindow struct {
	mu       sync.Mutex
	events   []rateEvent
	duration time.Duration
	lastSeen time.Time
}

func newRateWindow(d time.Duration) *rateWindow {
	return &rateWindow{duration: d}
}

// Add records a new observation and prunes events that fell out of the window.
func (r *rateWindow) Add(errored bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.events = append(r.events, rateEvent{ts: now, errored: errored})
	r.lastSeen = now
	r.prune(now)
}

// IdleSince returns the time of the most recent Add, or the zero value if
// nothing has been added. Used by the janitor to evict cold keys.
func (r *rateWindow) IdleSince() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastSeen
}

// Stats returns the total event count, error count, and error rate (0..1)
// within the current window. Also prunes expired events as a side effect.
func (r *rateWindow) Stats() (total, errors int, rate float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(time.Now())
	total = len(r.events)
	for _, e := range r.events {
		if e.errored {
			errors++
		}
	}
	if total > 0 {
		rate = float64(errors) / float64(total)
	}
	return
}

// ErrorCount returns only the error count in the window (cheaper than Stats
// when the total and rate are not needed — e.g. for drop-count thresholds).
func (r *rateWindow) ErrorCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(time.Now())
	n := 0
	for _, e := range r.events {
		if e.errored {
			n++
		}
	}
	return n
}

func (r *rateWindow) prune(now time.Time) {
	cutoff := now.Add(-r.duration)
	i := 0
	for i < len(r.events) && r.events[i].ts.Before(cutoff) {
		i++
	}
	if i > 0 {
		r.events = append(r.events[:0], r.events[i:]...)
	}
}
