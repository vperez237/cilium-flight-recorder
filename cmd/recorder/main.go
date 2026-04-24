package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/vperez237/cilium-flight-recorder/pkg/api"
	"github.com/vperez237/cilium-flight-recorder/pkg/capture"
	"github.com/vperez237/cilium-flight-recorder/pkg/config"
	"github.com/vperez237/cilium-flight-recorder/pkg/detector"
	"github.com/vperez237/cilium-flight-recorder/pkg/storage"
	"github.com/vperez237/cilium-flight-recorder/pkg/tracing"
	"github.com/vperez237/cilium-flight-recorder/pkg/watcher"
)

// version is stamped at build time via -ldflags. Defaults to "dev" for
// local/developer builds; shipped in span resource attributes and logs.
var version = "dev"

const pcapOutputDir = "/tmp/flight-recorder"

func main() {
	configPath := flag.String("config", "/etc/flight-recorder/config.yaml", "path to configuration file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tracerShutdown, err := tracing.Init(ctx, cfg.Tracing.Endpoint, "flight-recorder", version, cfg.Tracing.SampleRatio)
	if err != nil {
		// A tracing misconfiguration shouldn't block the pipeline — log it
		// and continue with the default no-op tracer.
		slog.Warn("tracing init failed; running without tracing", "error", err)
		tracerShutdown = func(context.Context) error { return nil }
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tracerShutdown(shutdownCtx)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	hw := watcher.NewHubbleWatcher(cfg.HubbleAddress, 4096, logger)

	ad := detector.NewAnomalyDetector(cfg.Triggers, cfg.Capture.CooldownSeconds, cfg.Detector, logger)

	cm, err := capture.NewCaptureManager(cfg.CiliumSocketPath, pcapOutputDir, cfg.Capture, cfg.Cilium, logger)
	if err != nil {
		slog.Error("failed to create capture manager", "error", err)
		os.Exit(1)
	}

	uploader, err := storage.NewS3Uploader(ctx, cfg.S3Bucket, cfg.S3Region, cfg.Cluster, cfg.S3Endpoint, cfg.Upload, logger)
	if err != nil {
		slog.Error("failed to create S3 uploader", "error", err)
		os.Exit(1)
	}

	srv := api.NewServer(cfg.Server.Port, cm, healthChecker{hw: hw}, logger)

	slog.Info("starting flight recorder",
		"cluster", cfg.Cluster,
		"hubble_address", cfg.HubbleAddress,
		"s3_bucket", cfg.S3Bucket,
		"api_port", cfg.Server.Port,
	)

	var wg sync.WaitGroup

	// 1. Hubble flow watcher
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := hw.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Error("hubble watcher stopped unexpectedly", "error", err)
			cancel()
		}
	}()

	// 2. Anomaly detector
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := ad.Run(ctx, hw.Flows()); err != nil && ctx.Err() == nil {
			slog.Error("anomaly detector stopped unexpectedly", "error", err)
			cancel()
		}
	}()

	// 3. Capture manager
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := cm.Run(ctx, ad.Captures()); err != nil && ctx.Err() == nil {
			slog.Error("capture manager stopped unexpectedly", "error", err)
			cancel()
		}
	}()

	// 4. S3 uploader — also records captures in the API server for listing
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case result, ok := <-cm.Results():
				if !ok {
					return
				}
				srv.RecordCapture(result)
				if err := uploader.Upload(ctx, result); err != nil {
					slog.Error("upload failed after retries; keeping local copy",
						"error", err,
						"file", result.FilePath,
					)
					continue
				}
				if err := os.Remove(result.FilePath); err != nil {
					slog.Warn("failed to remove local PCAP after upload",
						"error", err,
						"file", result.FilePath,
					)
				}
			}
		}
	}()

	// 5. HTTP API server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Error("API server stopped unexpectedly", "error", err)
			cancel()
		}
	}()

	wg.Wait()
	slog.Info("flight recorder stopped")
}

// healthChecker adapts the HubbleWatcher to the api.HealthChecker interface.
type healthChecker struct {
	hw *watcher.HubbleWatcher
}

func (h healthChecker) HubbleConnected() bool {
	return h.hw.Connected()
}
