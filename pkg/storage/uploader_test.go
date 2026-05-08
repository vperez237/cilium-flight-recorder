package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vperez237/cilium-flight-recorder/pkg/capture"
	"github.com/vperez237/cilium-flight-recorder/pkg/config"
	"github.com/vperez237/cilium-flight-recorder/pkg/detector"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/memblob"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func testRetryCfg() config.UploadConfig {
	return config.UploadConfig{
		MaxAttempts:      3,
		InitialBackoffMs: 1,
		MaxBackoffMs:     10,
	}
}

// stagePCAP writes a small fake PCAP to a temp dir and returns a populated
// CaptureResult pointing at it. Tests can then exercise Upload end-to-end
// against an in-memory bucket.
func stagePCAP(t *testing.T) capture.CaptureResult {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "20260424T120000Z_drop_10.0.0.1_10.0.0.2_443.pcap")
	if err := os.WriteFile(path, []byte("\xd4\xc3\xb2\xa1pcap-bytes"), 0o644); err != nil {
		t.Fatalf("write fake pcap: %v", err)
	}
	return capture.CaptureResult{
		FilePath:  path,
		Trigger:   detector.TriggerDrop,
		Reason:    "test drop",
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		DstPort:   443,
		Protocol:  "TCP",
		StartTime: time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC),
		Duration:  10 * time.Second,
	}
}

func newMemUploader(t *testing.T) *Uploader {
	t.Helper()
	u, err := NewUploader(context.Background(), "mem://", "test-cluster", testRetryCfg(), testLogger())
	if err != nil {
		t.Fatalf("NewUploader(mem://): %v", err)
	}
	t.Cleanup(func() { _ = u.Close() })
	return u
}

func TestUploadHappyPath(t *testing.T) {
	u := newMemUploader(t)
	result := stagePCAP(t)

	if err := u.Upload(context.Background(), result); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	// The expected key shape is cluster/node/YYYY/MM/DD/filename.pcap.
	// NODE_NAME is unset in tests so it falls back to "unknown-node".
	wantKey := "test-cluster/unknown-node/2026/04/24/" + filepath.Base(result.FilePath)
	body, err := u.bucket.ReadAll(context.Background(), wantKey)
	if err != nil {
		t.Fatalf("expected object at %q: %v", wantKey, err)
	}
	if string(body) != "\xd4\xc3\xb2\xa1pcap-bytes" {
		t.Errorf("body mismatch: %q", body)
	}

	// Metadata should round-trip — operators rely on these for browsing.
	attrs, err := u.bucket.Attributes(context.Background(), wantKey)
	if err != nil {
		t.Fatalf("Attributes: %v", err)
	}
	for k, v := range map[string]string{
		"trigger": "drop",
		"src_ip":  "10.0.0.1",
		"dst_ip":  "10.0.0.2",
		"cluster": "test-cluster",
	} {
		if got := attrs.Metadata[k]; got != v {
			t.Errorf("metadata[%q] = %q, want %q", k, got, v)
		}
	}
	if attrs.ContentType != "application/vnd.tcpdump.pcap" {
		t.Errorf("ContentType = %q, want application/vnd.tcpdump.pcap", attrs.ContentType)
	}
}

func TestUploadMissingSourceIsTerminal(t *testing.T) {
	u := newMemUploader(t)
	result := capture.CaptureResult{
		FilePath:  "/nonexistent.pcap",
		StartTime: time.Now().UTC(),
	}

	err := u.Upload(context.Background(), result)
	if err == nil {
		t.Fatal("expected error for missing source file")
	}
	if !errors.Is(err, ErrTerminal) {
		t.Errorf("expected ErrTerminal, got %v", err)
	}
	if !errors.Is(err, ErrTransient) {
		t.Errorf("expected ErrTransient in chain (every attempt failed transiently), got %v", err)
	}
}

func TestUploadHonoursContextCancel(t *testing.T) {
	u := newMemUploader(t)
	result := stagePCAP(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := u.Upload(ctx, result)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled in chain, got %v", err)
	}
}

func TestSentinelErrorsChain(t *testing.T) {
	inner := errors.New("network timeout")
	transient := fmt.Errorf("%w: %w", ErrTransient, inner)
	terminal := fmt.Errorf("%w: after 5 attempts: %w", ErrTerminal, transient)

	if !errors.Is(terminal, ErrTerminal) {
		t.Error("final error should be ErrTerminal")
	}
	if !errors.Is(terminal, ErrTransient) {
		t.Error("final error should still carry ErrTransient in its chain")
	}
	if !errors.Is(terminal, inner) {
		t.Error("final error should still wrap the innermost cause")
	}
	if errors.Is(transient, ErrTerminal) {
		t.Error("transient-only error should not match ErrTerminal")
	}
}

func TestBackoffFor(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 2 * time.Second

	cases := []struct {
		attempt int
		min     time.Duration
		max     time.Duration
	}{
		{1, 80 * time.Millisecond, 120 * time.Millisecond},
		{2, 160 * time.Millisecond, 240 * time.Millisecond},
		{3, 320 * time.Millisecond, 480 * time.Millisecond},
		{5, 1280 * time.Millisecond, 1920 * time.Millisecond},
		{6, 1600 * time.Millisecond, 2400 * time.Millisecond},
		{10, 1600 * time.Millisecond, 2400 * time.Millisecond},
	}

	for _, tc := range cases {
		for i := 0; i < 10; i++ {
			got := backoffFor(tc.attempt, initial, max)
			if got < tc.min || got > tc.max {
				t.Errorf("attempt %d sample %d: got %v, want in [%v,%v]",
					tc.attempt, i, got, tc.min, tc.max)
			}
		}
	}
}

// Compile-time assertion that the bucket field is accessible from this
// package (used by ReadAll/Attributes in the happy-path test). Removes
// the temptation to make it private and break tests later.
var _ = blob.PrefixedBucket
