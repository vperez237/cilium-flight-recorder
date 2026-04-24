package capture

import (
	"errors"
	"sync"
	"time"

	"github.com/vperez237/cilium-flight-recorder/pkg/metrics"
)

// circuitState is the three-state status of the Cilium-socket circuit breaker.
//
//   - closed:    requests flow through; failures accumulate.
//   - open:      requests fail fast without touching the socket until
//                cooldown elapses, so an unreachable agent can't pin every
//                capture goroutine to the 10s HTTP timeout.
//   - half-open: one probe request is allowed after cooldown; its outcome
//                decides whether to close (success) or re-open (failure).
type circuitState int32

const (
	stateClosed   circuitState = 0
	stateOpen     circuitState = 1
	stateHalfOpen circuitState = 2
)

// ErrCiliumUnavailable is returned by Cilium-socket operations when the
// circuit breaker has judged the agent unreachable. Callers can use
// errors.Is to distinguish "the agent is down" from other capture errors.
var ErrCiliumUnavailable = errors.New("cilium agent unavailable: circuit breaker open")

// circuitBreaker gates calls to the Cilium agent Unix socket. All methods
// are safe for concurrent use.
type circuitBreaker struct {
	mu               sync.Mutex
	state            circuitState
	consecutiveFails int
	openedAt         time.Time
	probeInFlight    bool

	threshold int
	cooldown  time.Duration
}

func newCircuitBreaker(threshold int, cooldown time.Duration) *circuitBreaker {
	if threshold < 1 {
		threshold = 1
	}
	if cooldown <= 0 {
		cooldown = time.Second
	}
	metrics.CiliumCircuitState.Set(float64(stateClosed))
	return &circuitBreaker{threshold: threshold, cooldown: cooldown}
}

// allow reports whether a request should proceed. If it returns nil, the
// caller must call report() with the resulting error. If it returns
// ErrCiliumUnavailable, the caller must NOT call report() — no request was made.
func (c *circuitBreaker) allow() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch c.state {
	case stateClosed:
		return nil

	case stateOpen:
		if time.Since(c.openedAt) < c.cooldown {
			metrics.CiliumShortCircuited.Inc()
			return ErrCiliumUnavailable
		}
		// Cooldown expired: promote to half-open and let exactly one probe through.
		c.state = stateHalfOpen
		c.probeInFlight = true
		metrics.CiliumCircuitState.Set(float64(stateHalfOpen))
		return nil

	case stateHalfOpen:
		// A probe is already in flight; anything else fails fast so we don't
		// mistakenly declare the breaker healthy from a coincidentally
		// successful second request.
		if c.probeInFlight {
			metrics.CiliumShortCircuited.Inc()
			return ErrCiliumUnavailable
		}
		c.probeInFlight = true
		return nil
	}
	return ErrCiliumUnavailable
}

// report records the outcome of a request allow()'d earlier.
func (c *circuitBreaker) report(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err == nil {
		// Success closes the breaker regardless of previous state.
		c.consecutiveFails = 0
		if c.state != stateClosed {
			c.state = stateClosed
			metrics.CiliumCircuitState.Set(float64(stateClosed))
		}
		c.probeInFlight = false
		return
	}

	// Half-open probe failed: re-open for a full cooldown.
	if c.state == stateHalfOpen {
		c.state = stateOpen
		c.openedAt = time.Now()
		c.probeInFlight = false
		metrics.CiliumCircuitState.Set(float64(stateOpen))
		metrics.CiliumCircuitTrips.Inc()
		return
	}

	c.consecutiveFails++
	if c.consecutiveFails >= c.threshold && c.state == stateClosed {
		c.state = stateOpen
		c.openedAt = time.Now()
		metrics.CiliumCircuitState.Set(float64(stateOpen))
		metrics.CiliumCircuitTrips.Inc()
	}
}
