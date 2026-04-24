package main

import (
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Mock Hubble Relay gRPC server that generates a stream of realistic-looking
// flow events — a mix of normal traffic with periodic anomalies (drops, 5xx,
// DNS failures) to exercise the flight recorder's anomaly detector.

type mockObserver struct {
	observerpb.UnimplementedObserverServer
	logger *slog.Logger
}

func (m *mockObserver) GetFlows(req *observerpb.GetFlowsRequest, stream observerpb.Observer_GetFlowsServer) error {
	m.logger.Info("client connected to mock hubble relay", "follow", req.GetFollow())

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	seq := 0
	for {
		select {
		case <-stream.Context().Done():
			m.logger.Info("client disconnected")
			return nil
		case <-ticker.C:
			flow := m.generateFlow(seq)
			resp := &observerpb.GetFlowsResponse{
				ResponseTypes: &observerpb.GetFlowsResponse_Flow{
					Flow: flow,
				},
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
			seq++
		}
	}
}

func (m *mockObserver) generateFlow(seq int) *flowpb.Flow {
	now := timestamppb.Now()

	// Every 20th flow is a drop. To exercise rate-based detection, pin 70%
	// of drops to a fixed destination so a meaningful error rate accumulates.
	if seq%20 == 0 {
		m.logger.Info("generating DROP flow", "seq", seq)
		dstIP := "10.0.2.200"
		if rand.Intn(10) < 3 {
			dstIP = randIP("10.0.2")
		}
		return &flowpb.Flow{
			Time:    now,
			Verdict: flowpb.Verdict_DROPPED,
			DropReason: 181,
			DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
			IP: &flowpb.IP{
				Source:      randIP("10.0.1"),
				Destination: dstIP,
			},
			L4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_TCP{
					TCP: &flowpb.TCP{
						SourcePort:      uint32(30000 + rand.Intn(30000)),
						DestinationPort: 8080,
					},
				},
			},
			Source: &flowpb.Endpoint{
				Namespace: "app-dev",
				PodName:   "frontend-abc123",
				Labels:    []string{"app=frontend"},
			},
			Destination: &flowpb.Endpoint{
				Namespace: "app-dev",
				PodName:   "backend-def456",
				Labels:    []string{"app=backend"},
			},
		}
	}

	// Every 30th flow is an HTTP 503 — pin to a fixed backend so rate-based
	// detection has enough samples per key to compute a meaningful ratio.
	if seq%30 == 0 {
		m.logger.Info("generating HTTP 503 flow", "seq", seq)
		return &flowpb.Flow{
			Time:    now,
			Verdict: flowpb.Verdict_FORWARDED,
			IP: &flowpb.IP{
				Source:      randIP("10.0.1"),
				Destination: "10.0.2.201",
			},
			L4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_TCP{
					TCP: &flowpb.TCP{
						SourcePort:      uint32(30000 + rand.Intn(30000)),
						DestinationPort: 443,
					},
				},
			},
			L7: &flowpb.Layer7{
				LatencyNs: uint64(time.Duration(rand.Intn(500)+100) * time.Millisecond),
				Record: &flowpb.Layer7_Http{
					Http: &flowpb.HTTP{
						Code:     503,
						Method:   "GET",
						Url:      "/api/v1/events",
						Protocol: "HTTP/1.1",
					},
				},
			},
			Source: &flowpb.Endpoint{
				Namespace: "app-dev",
				PodName:   "gateway-xyz789",
				Labels:    []string{"app=gateway"},
			},
			Destination: &flowpb.Endpoint{
				Namespace: "app-dev",
				PodName:   "events-api-ijk012",
				Labels:    []string{"app=events-api"},
			},
		}
	}

	// Every 50th flow is a DNS NXDOMAIN
	if seq%50 == 0 {
		m.logger.Info("generating DNS NXDOMAIN flow", "seq", seq)
		return &flowpb.Flow{
			Time:    now,
			Verdict: flowpb.Verdict_FORWARDED,
			IP: &flowpb.IP{
				Source:      randIP("10.0.1"),
				Destination: "10.0.0.2",
			},
			L4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_UDP{
					UDP: &flowpb.UDP{
						SourcePort:      uint32(30000 + rand.Intn(30000)),
						DestinationPort: 53,
					},
				},
			},
			L7: &flowpb.Layer7{
				Record: &flowpb.Layer7_Dns{
					Dns: &flowpb.DNS{
						Query:  "nonexistent-service.app-dev.svc.cluster.local.",
						Rcode:  3, // NXDOMAIN
						ObservationSource: "proxy",
					},
				},
			},
			Source: &flowpb.Endpoint{
				Namespace: "app-dev",
				PodName:   "frontend-abc123",
				Labels:    []string{"app=frontend"},
			},
			Destination: &flowpb.Endpoint{
				Namespace: "kube-system",
				PodName:   "coredns-aaa111",
				Labels:    []string{"k8s-app=kube-dns"},
			},
		}
	}

	// Every 7th flow is a high-latency request from a fixed src/dst pair.
	// After ~10 of these fill the sliding window, P99 crosses the threshold.
	if seq%7 == 0 {
		latency := time.Duration(2500+rand.Intn(2000)) * time.Millisecond
		m.logger.Info("generating HIGH LATENCY flow", "seq", seq, "latency_ms", latency.Milliseconds())
		return &flowpb.Flow{
			Time:    now,
			Verdict: flowpb.Verdict_FORWARDED,
			IP: &flowpb.IP{
				Source:      "10.0.1.50",
				Destination: "10.0.2.50",
			},
			L4: &flowpb.Layer4{
				Protocol: &flowpb.Layer4_TCP{
					TCP: &flowpb.TCP{
						SourcePort:      uint32(30000 + rand.Intn(30000)),
						DestinationPort: 9090,
					},
				},
			},
			L7: &flowpb.Layer7{
				LatencyNs: uint64(latency),
				Record: &flowpb.Layer7_Http{
					Http: &flowpb.HTTP{
						Code:     200,
						Method:   "POST",
						Url:      "/api/v1/checkout",
						Protocol: "HTTP/1.1",
					},
				},
			},
			Source: &flowpb.Endpoint{
				Namespace: "app-dev",
				PodName:   "checkout-ui-aaa111",
				Labels:    []string{"app=checkout-ui"},
			},
			Destination: &flowpb.Endpoint{
				Namespace: "app-dev",
				PodName:   "payment-svc-bbb222",
				Labels:    []string{"app=payment-svc"},
			},
		}
	}

	// Normal forwarded traffic (low latency). A portion targets the fixed
	// HTTP backend (10.0.2.201) so the HTTP rate-based detector has a
	// meaningful denominator for its error-rate calculation.
	dstIP := randIP("10.0.2")
	if rand.Intn(10) < 5 {
		dstIP = "10.0.2.201"
	}
	return &flowpb.Flow{
		Time:    now,
		Verdict: flowpb.Verdict_FORWARDED,
		IP: &flowpb.IP{
			Source:      randIP("10.0.1"),
			Destination: dstIP,
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					SourcePort:      uint32(30000 + rand.Intn(30000)),
					DestinationPort: 8080,
				},
			},
		},
		L7: &flowpb.Layer7{
			LatencyNs: uint64(time.Duration(rand.Intn(50)+5) * time.Millisecond),
			Record: &flowpb.Layer7_Http{
				Http: &flowpb.HTTP{
					Code:     200,
					Method:   "GET",
					Url:      "/api/v1/health",
					Protocol: "HTTP/1.1",
				},
			},
		},
		Source: &flowpb.Endpoint{
			Namespace: "app-dev",
			PodName:   "frontend-abc123",
			Labels:    []string{"app=frontend"},
		},
		Destination: &flowpb.Endpoint{
			Namespace: "app-dev",
			PodName:   "backend-def456",
			Labels:    []string{"app=backend"},
		},
	}
}

func randIP(prefix string) string {
	return fmt.Sprintf("%s.%d", prefix, rand.Intn(254)+1)
}

func main() {
	listenAddr := os.Getenv("HUBBLE_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":4245"
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logger.Error("failed to listen", "error", err, "addr", listenAddr)
		os.Exit(1)
	}

	server := grpc.NewServer()
	observerpb.RegisterObserverServer(server, &mockObserver{logger: logger})

	logger.Info("mock hubble relay started", "addr", listenAddr)

	if err := server.Serve(listener); err != nil {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}
