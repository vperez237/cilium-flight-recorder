// Package storage uploads completed PCAPs to object storage. The destination
// is selected by a gocloud.dev/blob URL (s3://, gs://, azblob://, mem://),
// so the same code paths handle AWS S3, Google Cloud Storage, Azure Blob,
// and in-memory buckets used by tests.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"gocloud.dev/blob"
	// Driver registrations. Each blank import wires its scheme into the
	// gocloud blob registry so blob.OpenBucket can dispatch on the URL.
	_ "gocloud.dev/blob/azureblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/memblob"
	_ "gocloud.dev/blob/s3blob"

	"github.com/vperez237/cilium-flight-recorder/pkg/capture"
	"github.com/vperez237/cilium-flight-recorder/pkg/config"
	"github.com/vperez237/cilium-flight-recorder/pkg/metrics"
	"github.com/vperez237/cilium-flight-recorder/pkg/tracing"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Sentinel errors so callers can distinguish "give it another try later"
// from "this PCAP is staying on local disk until an operator deals with it".
var (
	// ErrTransient wraps an error from a single upload attempt that may
	// succeed on retry (network blip, 5xx, throttling).
	ErrTransient = errors.New("upload: transient failure")
	// ErrTerminal wraps the final error after all retry attempts are
	// exhausted, or when ctx was cancelled.
	ErrTerminal = errors.New("upload: terminal failure")
)

// Uploader pushes capture results into a gocloud.dev/blob bucket with
// jittered exponential-backoff retries. The bucket can point at any
// gocloud-supported backend (S3 / GCS / Azure Blob / in-memory / fs).
type Uploader struct {
	bucket   *blob.Bucket
	cluster  string
	nodeName string
	logger   *slog.Logger
	retryCfg config.UploadConfig
}

// NewUploader opens a bucket from a gocloud.dev URL. Examples:
//
//	s3://my-pcaps?region=us-east-1
//	s3://my-pcaps?region=us-east-1&endpoint=http://minio:9000&s3ForcePathStyle=true&disableSSL=true&awssdk=v2
//	gs://my-pcaps
//	azblob://my-pcaps?domain=blob.core.windows.net
//	mem://                                          (tests)
//
// Authentication uses each cloud's default credential chain (IRSA on EKS,
// Workload Identity on GKE/AKS, env vars / service-account JSON otherwise).
func NewUploader(ctx context.Context, blobURL, cluster string, retryCfg config.UploadConfig, logger *slog.Logger) (*Uploader, error) {
	bucket, err := blob.OpenBucket(ctx, blobURL)
	if err != nil {
		return nil, fmt.Errorf("opening bucket %q: %w", blobURL, err)
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName = "unknown-node"
	}

	return &Uploader{
		bucket:   bucket,
		cluster:  cluster,
		nodeName: nodeName,
		logger:   logger.With("component", "uploader"),
		retryCfg: retryCfg,
	}, nil
}

// Close releases the underlying bucket connection. Safe to call once at
// shutdown; subsequent Upload calls will fail.
func (u *Uploader) Close() error {
	return u.bucket.Close()
}

// Upload writes one PCAP to the bucket, retrying transient failures with
// jittered exponential backoff. The final error wraps ErrTerminal; per-
// attempt errors wrap ErrTransient. Caller is responsible for what to do
// with the local file on terminal failure (typically: keep it).
func (u *Uploader) Upload(ctx context.Context, result capture.CaptureResult) error {
	ctx, span := tracing.Tracer().Start(ctx, "blob.Upload",
		trace.WithAttributes(
			attribute.String("trigger", string(result.Trigger)),
			attribute.String("cluster", u.cluster),
			attribute.String("node", u.nodeName),
		),
	)
	defer span.End()

	initial := time.Duration(u.retryCfg.InitialBackoffMs) * time.Millisecond
	maxBackoff := time.Duration(u.retryCfg.MaxBackoffMs) * time.Millisecond
	start := time.Now()

	var lastErr error
	for attempt := 1; attempt <= u.retryCfg.MaxAttempts; attempt++ {
		attemptCtx, attemptSpan := tracing.Tracer().Start(ctx, "blob.Upload.attempt",
			trace.WithAttributes(attribute.Int("attempt", attempt)),
		)
		size, err := u.upload(attemptCtx, result)
		if err == nil {
			attemptSpan.SetAttributes(attribute.Int64("size_bytes", size))
			attemptSpan.End()
			span.SetAttributes(attribute.Int("attempts", attempt), attribute.Int64("size_bytes", size))
			metrics.UploadAttempts.WithLabelValues("success").Inc()
			metrics.RecordUploadSuccess(time.Since(start).Seconds(), float64(size))
			return nil
		}
		attemptSpan.RecordError(err)
		attemptSpan.SetStatus(codes.Error, "attempt failed")
		attemptSpan.End()
		lastErr = err

		// Never retry if the caller is shutting down.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			metrics.UploadAttempts.WithLabelValues("terminal").Inc()
			metrics.RecordUploadFailure()
			return fmt.Errorf("%w: %w", ErrTerminal, err)
		}
		if attempt == u.retryCfg.MaxAttempts {
			metrics.UploadAttempts.WithLabelValues("terminal").Inc()
			metrics.RecordUploadFailure()
			break
		}

		metrics.UploadAttempts.WithLabelValues("retryable").Inc()
		metrics.RecordUploadRetry()

		wait := backoffFor(attempt, initial, maxBackoff)
		u.logger.Warn("upload failed, retrying",
			"error", err,
			"attempt", attempt,
			"max_attempts", u.retryCfg.MaxAttempts,
			"backoff", wait,
			"file", result.FilePath,
		)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}

	span.RecordError(lastErr)
	span.SetStatus(codes.Error, "all upload attempts failed")
	return fmt.Errorf("%w: after %d attempts: %w", ErrTerminal, u.retryCfg.MaxAttempts, lastErr)
}

// backoffFor returns initial * 2^(attempt-1) capped at max, with ±20% jitter.
func backoffFor(attempt int, initial, max time.Duration) time.Duration {
	d := initial
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= max {
			d = max
			break
		}
	}
	jitter := 1.0 + (rand.Float64()*0.4 - 0.2)
	return time.Duration(float64(d) * jitter)
}

// Run consumes capture results from a channel and uploads them, leaving
// failed PCAPs on local disk so an operator (or a follow-up job) can retry
// them out-of-band.
func (u *Uploader) Run(ctx context.Context, results <-chan capture.CaptureResult) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result, ok := <-results:
			if !ok {
				return nil
			}
			if err := u.Upload(ctx, result); err != nil {
				u.logger.Error("failed to upload PCAP; keeping local copy",
					"error", err,
					"file", result.FilePath,
				)
				continue
			}
			if err := os.Remove(result.FilePath); err != nil {
				u.logger.Warn("failed to remove local PCAP after upload",
					"error", err,
					"file", result.FilePath,
				)
			}
		}
	}
}

// upload performs one attempt. Metrics other than per-attempt logging are
// intentionally not recorded here — aggregate recording lives in Upload.
func (u *Uploader) upload(ctx context.Context, result capture.CaptureResult) (int64, error) {
	f, err := os.Open(result.FilePath)
	if err != nil {
		return 0, fmt.Errorf("%w: opening PCAP file: %w", ErrTransient, err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("%w: stat PCAP file: %w", ErrTransient, err)
	}
	fileSize := stat.Size()

	// Date split into YYYY/MM/DD path segments so prefix-based lifecycle
	// rules and operator browsing (`aws s3 ls bucket/cluster/node/2026/`)
	// work without parsing filenames. Same key shape on every backend.
	datePath := result.StartTime.UTC().Format("2006/01/02")
	filename := filepath.Base(result.FilePath)
	key := fmt.Sprintf("%s/%s/%s/%s", u.cluster, u.nodeName, datePath, filename)

	// Use underscored keys throughout — Azure Blob metadata keys must
	// match C# identifier rules (letters, digits, underscores; no hyphens),
	// and S3+GCS accept them without complaint. Hyphenated keys would
	// fail the Azure path; the inconsistency would surprise operators.
	metadata := map[string]string{
		"trigger":  string(result.Trigger),
		"reason":   result.Reason,
		"src_ip":   result.SrcIP,
		"dst_ip":   result.DstIP,
		"dst_port": fmt.Sprintf("%d", result.DstPort),
		"protocol": result.Protocol,
		"duration": result.Duration.String(),
		"node":     u.nodeName,
		"cluster":  u.cluster,
		"captured": result.StartTime.UTC().Format(time.RFC3339),
	}

	w, err := u.bucket.NewWriter(ctx, key, &blob.WriterOptions{
		ContentType: "application/vnd.tcpdump.pcap",
		Metadata:    metadata,
	})
	if err != nil {
		return 0, fmt.Errorf("%w: creating writer for %s: %w", ErrTransient, key, err)
	}

	if _, err := io.Copy(w, f); err != nil {
		// Close to release the underlying transport even on copy failure;
		// the second close error is ignored — the IO error is what matters.
		_ = w.Close()
		return 0, fmt.Errorf("%w: writing object %s: %w", ErrTransient, key, err)
	}
	if err := w.Close(); err != nil {
		return 0, fmt.Errorf("%w: finalizing object %s: %w", ErrTransient, key, err)
	}

	u.logger.Info("uploaded PCAP",
		"key", key,
		"size_bytes", fileSize,
		"trigger", result.Trigger,
	)

	return fileSize, nil
}
