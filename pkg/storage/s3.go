package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/vperez237/cilium-flight-recorder/pkg/capture"
	"github.com/vperez237/cilium-flight-recorder/pkg/config"
	"github.com/vperez237/cilium-flight-recorder/pkg/metrics"
	"github.com/vperez237/cilium-flight-recorder/pkg/tracing"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Sentinel errors for S3 uploads. Callers can distinguish transient failures
// (worth retrying or alerting softly) from terminal ones (operator action
// needed) via errors.Is.
var (
	// ErrS3Transient wraps an error from an individual upload attempt that
	// may succeed on retry (network blip, 5xx, throttling).
	ErrS3Transient = errors.New("s3 upload: transient failure")
	// ErrS3Terminal wraps the final error after all retry attempts are
	// exhausted, or when ctx was cancelled.
	ErrS3Terminal = errors.New("s3 upload: terminal failure")
)

// S3Uploader watches for completed PCAP files and uploads them to S3.
type S3Uploader struct {
	bucket    string
	cluster   string
	nodeName  string
	client    *s3.Client
	logger    *slog.Logger
	retryCfg  config.UploadConfig
}

func NewS3Uploader(ctx context.Context, bucket, region, cluster, endpoint string, retryCfg config.UploadConfig, logger *slog.Logger) (*S3Uploader, error) {
	// IRSA injects AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE; the default
	// credential chain picks these up automatically.
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	var s3Opts []func(*s3.Options)
	if endpoint != "" {
		// Custom endpoint for local development (MinIO, LocalStack, etc.)
		s3Opts = append(s3Opts,
			func(o *s3.Options) {
				o.BaseEndpoint = &endpoint
				o.UsePathStyle = true
			},
		)
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName = "unknown-node"
	}

	return &S3Uploader{
		bucket:   bucket,
		cluster:  cluster,
		nodeName: nodeName,
		client:   s3.NewFromConfig(cfg, s3Opts...),
		logger:   logger.With("component", "s3-uploader"),
		retryCfg: retryCfg,
	}, nil
}

// Upload uploads a single capture result to S3, retrying transient failures
// with jittered exponential backoff. Returns the last error if all attempts
// fail; the caller is responsible for deciding what to do with the local file.
func (u *S3Uploader) Upload(ctx context.Context, result capture.CaptureResult) error {
	ctx, span := tracing.Tracer().Start(ctx, "s3.Upload",
		trace.WithAttributes(
			attribute.String("trigger", string(result.Trigger)),
			attribute.String("bucket", u.bucket),
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
		attemptCtx, attemptSpan := tracing.Tracer().Start(ctx, "s3.Upload.attempt",
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
			return fmt.Errorf("%w: %w", ErrS3Terminal, err)
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
	return fmt.Errorf("%w: after %d attempts: %w", ErrS3Terminal, u.retryCfg.MaxAttempts, lastErr)
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

// Run consumes capture results from a channel and uploads them to S3,
// leaving failed PCAPs on local disk so an operator (or a follow-up job)
// can retry them out-of-band.
func (u *S3Uploader) Run(ctx context.Context, results <-chan capture.CaptureResult) error {
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

// upload performs one attempt at uploading a PCAP. It returns the uploaded
// byte count on success so the caller can aggregate metrics across retries.
// Metrics other than debug logging are intentionally not recorded here —
// aggregate recording lives in Upload.
func (u *S3Uploader) upload(ctx context.Context, result capture.CaptureResult) (int64, error) {
	f, err := os.Open(result.FilePath)
	if err != nil {
		return 0, fmt.Errorf("%w: opening PCAP file: %w", ErrS3Transient, err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("%w: stat PCAP file: %w", ErrS3Transient, err)
	}
	fileSize := stat.Size()

	// Split the date into YYYY/MM/DD path segments so prefix-based S3
	// lifecycle rules (e.g. "delete cluster/*/2024/*") and operator browsing
	// (`aws s3 ls bucket/cluster/node/2026/`) work without parsing filenames.
	datePath := result.StartTime.UTC().Format("2006/01/02")
	filename := filepath.Base(result.FilePath)
	key := fmt.Sprintf("%s/%s/%s/%s", u.cluster, u.nodeName, datePath, filename)

	metadata := map[string]string{
		"trigger":  string(result.Trigger),
		"reason":   result.Reason,
		"src-ip":   result.SrcIP,
		"dst-ip":   result.DstIP,
		"dst-port": fmt.Sprintf("%d", result.DstPort),
		"protocol": result.Protocol,
		"duration": result.Duration.String(),
		"node":     u.nodeName,
		"cluster":  u.cluster,
		"captured": result.StartTime.UTC().Format(time.RFC3339),
	}

	contentType := "application/vnd.tcpdump.pcap"

	_, err = u.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        &u.bucket,
		Key:           &key,
		Body:          f,
		ContentLength: &fileSize,
		ContentType:   &contentType,
		Metadata:      metadata,
	})
	if err != nil {
		return 0, fmt.Errorf("%w: uploading to S3: %w", ErrS3Transient, err)
	}

	u.logger.Info("uploaded PCAP to S3",
		"bucket", u.bucket,
		"key", key,
		"size_bytes", fileSize,
		"trigger", result.Trigger,
	)

	return fileSize, nil
}

// S3Key returns the full S3 URI for a given key.
func (u *S3Uploader) S3Key(key string) string {
	return fmt.Sprintf("s3://%s/%s", u.bucket, key)
}
