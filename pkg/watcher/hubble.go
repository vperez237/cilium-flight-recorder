package watcher

import (
	"context"
	"log/slog"
	"math"
	"sync/atomic"
	"time"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/vperez237/cilium-flight-recorder/pkg/metrics"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// gRPC keepalive: send a ping every 30s when the stream is idle and require
// an ACK within 10s. Without this the client can sit on a dead TCP connection
// for up to 2 hours (default OS keepalive) before noticing the Hubble relay
// is gone, during which no flows flow and no reconnect happens.
var hubbleKeepalive = keepalive.ClientParameters{
	Time:                30 * time.Second,
	Timeout:             10 * time.Second,
	PermitWithoutStream: false,
}

// FlowEvent is a lightweight wrapper around a Hubble flow for downstream consumption.
type FlowEvent struct {
	Flow      *observerpb.Flow
	Timestamp time.Time
}

// HubbleWatcher connects to Hubble Relay via gRPC and streams flow events.
type HubbleWatcher struct {
	address   string
	flowCh    chan FlowEvent
	logger    *slog.Logger
	connected atomic.Bool
}

// Connected reports whether the Hubble gRPC stream is currently established.
func (w *HubbleWatcher) Connected() bool {
	return w.connected.Load()
}

func (w *HubbleWatcher) setConnected(v bool) {
	w.connected.Store(v)
	if v {
		metrics.HubbleConnected.Set(1)
	} else {
		metrics.HubbleConnected.Set(0)
	}
}

func NewHubbleWatcher(address string, bufferSize int, logger *slog.Logger) *HubbleWatcher {
	if bufferSize <= 0 {
		bufferSize = 4096
	}
	return &HubbleWatcher{
		address: address,
		flowCh:  make(chan FlowEvent, bufferSize),
		logger:  logger.With("component", "hubble-watcher"),
	}
}

// Flows returns a read-only channel of flow events.
func (w *HubbleWatcher) Flows() <-chan FlowEvent {
	return w.flowCh
}

// Run connects to Hubble Relay and streams flows until ctx is cancelled.
// Reconnects automatically with exponential backoff on failure.
func (w *HubbleWatcher) Run(ctx context.Context) error {
	defer close(w.flowCh)

	var attempt int
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		err := w.stream(ctx)
		if err == nil || ctx.Err() != nil {
			return ctx.Err()
		}

		backoff := w.backoffDuration(attempt)
		w.logger.Warn("hubble stream disconnected, reconnecting",
			"error", err,
			"attempt", attempt,
			"backoff", backoff,
		)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		attempt++
	}
}

func (w *HubbleWatcher) stream(ctx context.Context) error {
	conn, err := grpc.NewClient(w.address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(hubbleKeepalive),
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := observerpb.NewObserverClient(conn)

	stream, err := client.GetFlows(ctx, &observerpb.GetFlowsRequest{
		Follow: true,
	})
	if err != nil {
		return err
	}

	w.logger.Info("connected to hubble relay", "address", w.address)
	w.setConnected(true)
	defer w.setConnected(false)

	for {
		resp, err := stream.Recv()
		if err != nil {
			st, ok := status.FromError(err)
			if ok && st.Code() == codes.Canceled {
				return nil
			}
			return err
		}

		flow := resp.GetFlow()
		if flow == nil {
			continue
		}

		event := FlowEvent{
			Flow:      flow,
			Timestamp: flow.GetTime().AsTime(),
		}

		select {
		case w.flowCh <- event:
		default:
			metrics.FlowsDropped.Inc()
			w.logger.Warn("flow channel full, dropping event")
		}
	}
}

func (w *HubbleWatcher) backoffDuration(attempt int) time.Duration {
	base := float64(time.Second)
	max := float64(30 * time.Second)
	d := base * math.Pow(2, float64(attempt))
	if d > max {
		d = max
	}
	return time.Duration(d)
}
