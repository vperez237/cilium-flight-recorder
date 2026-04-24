package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// TriggersFired counts the number of times each trigger type was fired.
	TriggersFired = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flight_recorder_triggers_fired_total",
			Help: "Total number of times each trigger type was fired",
		},
		[]string{"trigger"},
	)

	// CapturesStarted counts the number of captures started.
	CapturesStarted = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flight_recorder_captures_started_total",
			Help: "Total number of captures started",
		},
		[]string{"trigger"},
	)

	// CapturesCompleted counts the number of captures completed successfully.
	CapturesCompleted = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flight_recorder_captures_completed_total",
			Help: "Total number of captures completed successfully",
		},
		[]string{"trigger"},
	)

	// CapturesFailed counts the number of captures that failed.
	CapturesFailed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flight_recorder_captures_failed_total",
			Help: "Total number of captures that failed",
		},
		[]string{"trigger", "reason"},
	)

	// CaptureDuration tracks the duration of captures.
	CaptureDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "flight_recorder_capture_duration_seconds",
			Help:    "Duration of captures in seconds",
			Buckets: []float64{5, 10, 30, 60, 120, 300, 600},
		},
		[]string{"trigger"},
	)

	// ActiveCaptures tracks the current number of active captures.
	ActiveCaptures = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "flight_recorder_active_captures",
			Help: "Current number of active captures",
		},
	)

	// UploadsTotal counts the total number of upload attempts.
	UploadsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flight_recorder_uploads_total",
			Help: "Total number of upload attempts",
		},
		[]string{"status"}, // "success", "failure", "retry"
	)

	// UploadRetries counts the number of retries performed.
	UploadRetries = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "flight_recorder_upload_retries_total",
			Help: "Total number of upload retries",
		},
	)

	// UploadDuration tracks the duration of uploads.
	UploadDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "flight_recorder_upload_duration_seconds",
			Help:    "Duration of uploads in seconds",
			Buckets: []float64{0.5, 1, 2, 5, 10, 30, 60},
		},
	)

	// UploadBytesTotal tracks the total bytes uploaded.
	UploadBytesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "flight_recorder_upload_bytes_total",
			Help: "Total bytes uploaded to S3",
		},
	)

	// LocalFallbackFiles tracks the number of files in local fallback storage.
	LocalFallbackFiles = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "flight_recorder_local_fallback_files",
			Help: "Number of files currently in local fallback storage",
		},
	)

	// LocalFallbackSize tracks the total size of files in local fallback storage.
	LocalFallbackSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "flight_recorder_local_fallback_bytes",
			Help: "Total size of files in local fallback storage in bytes",
		},
	)

	// FlowsProcessed counts the total flows processed by the detector.
	FlowsProcessed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "flight_recorder_flows_processed_total",
			Help: "Total number of flows processed by the detector",
		},
	)

	// AnomaliesDetected counts flows that triggered anomaly detection.
	AnomaliesDetected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flight_recorder_anomalies_detected_total",
			Help: "Total number of flows that triggered anomaly detection",
		},
		[]string{"trigger"},
	)

	// RateWindowErrors tracks error rates in rate mode.
	RateWindowErrors = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "flight_recorder_rate_window_error_rate",
			Help: "Current error rate in rate windows",
		},
		[]string{"trigger"},
	)

	// FlowsDropped counts flows dropped by the watcher because the consumer channel was full.
	FlowsDropped = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "flight_recorder_flows_dropped_total",
			Help: "Total number of flows dropped because the watcher's buffer was full",
		},
	)

	// CaptureRequestsDropped counts capture requests dropped because the capture manager's channel was full.
	CaptureRequestsDropped = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flight_recorder_capture_requests_dropped_total",
			Help: "Total number of capture requests dropped due to back-pressure",
		},
		[]string{"trigger"},
	)

	// HubbleConnected is 1 when the Hubble gRPC stream is connected, 0 otherwise.
	HubbleConnected = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "flight_recorder_hubble_connected",
			Help: "1 if the Hubble gRPC stream is connected, 0 otherwise",
		},
	)

	// TrackedKeys reports the current size of each per-tuple map inside the
	// anomaly detector. Used to verify the janitor keeps memory bounded.
	TrackedKeys = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "flight_recorder_tracked_keys",
			Help: "Number of keys currently tracked in each per-tuple map",
		},
		[]string{"map"},
	)

	// KeysEvicted counts keys removed by the janitor. `reason` is either
	// "idle" (last-seen older than idleTTL) or "capacity" (map exceeded cap).
	KeysEvicted = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flight_recorder_keys_evicted_total",
			Help: "Keys evicted by the detector janitor",
		},
		[]string{"map", "reason"},
	)

	// UploadAttempts counts individual upload attempts including retries,
	// labeled by the outcome of that specific attempt.
	UploadAttempts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flight_recorder_upload_attempts_total",
			Help: "Individual upload attempts including retries",
		},
		[]string{"outcome"}, // "success", "retryable", "terminal"
	)

	// CiliumCircuitState is the current circuit-breaker state protecting the
	// Cilium agent socket (0=closed, 1=open, 2=half-open).
	CiliumCircuitState = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "flight_recorder_cilium_circuit_state",
			Help: "Cilium agent circuit breaker state (0=closed, 1=open, 2=half-open)",
		},
	)

	// CiliumCircuitTrips counts the number of times the breaker has opened.
	CiliumCircuitTrips = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "flight_recorder_cilium_circuit_trips_total",
			Help: "Number of times the Cilium circuit breaker has opened",
		},
	)

	// CiliumShortCircuited counts requests that were failed fast because
	// the breaker was open (i.e. never actually hit the Cilium socket).
	CiliumShortCircuited = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "flight_recorder_cilium_short_circuited_total",
			Help: "Cilium API requests rejected by the open circuit breaker",
		},
	)
)

// RecordTriggerFired increments the trigger fired counter.
func RecordTriggerFired(trigger string) {
	TriggersFired.WithLabelValues(trigger).Inc()
}

// RecordCaptureStarted increments the captures started counter.
func RecordCaptureStarted(trigger string) {
	CapturesStarted.WithLabelValues(trigger).Inc()
}

// RecordCaptureCompleted records a successful capture.
func RecordCaptureCompleted(trigger string, durationSeconds float64) {
	CapturesCompleted.WithLabelValues(trigger).Inc()
	CaptureDuration.WithLabelValues(trigger).Observe(durationSeconds)
}

// RecordCaptureFailed records a failed capture.
func RecordCaptureFailed(trigger, reason string) {
	CapturesFailed.WithLabelValues(trigger, reason).Inc()
}

// RecordUploadSuccess records a successful upload.
func RecordUploadSuccess(durationSeconds, bytes float64) {
	UploadsTotal.WithLabelValues("success").Inc()
	UploadDuration.Observe(durationSeconds)
	UploadBytesTotal.Add(bytes)
}

// RecordUploadFailure records a failed upload (no retry).
func RecordUploadFailure() {
	UploadsTotal.WithLabelValues("failure").Inc()
}

// RecordUploadRetry records an upload retry.
func RecordUploadRetry() {
	UploadsTotal.WithLabelValues("retry").Inc()
	UploadRetries.Inc()
}
