// Package tracing wires OpenTelemetry into the flight recorder.
//
// When the configured endpoint is empty, Init installs a no-op tracer — the
// spans created via Tracer() become zero-cost. Turning tracing on at runtime
// is therefore a config change away, no code motion required.
package tracing

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// tracerName is the instrumentation-library name reported with every span.
const tracerName = "github.com/vperez237/cilium-flight-recorder"

// Init configures a tracer provider.
//
//   - If endpoint is empty, a no-op tracer is installed and the returned
//     shutdown function is a no-op. Callers can always use tracing.Tracer()
//     safely, and spans cost ~nothing.
//   - Otherwise an OTLP/gRPC exporter is created against the endpoint with a
//     parent-based TraceIDRatio sampler.
//
// The caller is expected to defer shutdown() so pending spans drain before
// the process exits.
func Init(ctx context.Context, endpoint, serviceName, serviceVersion string, sampleRatio float64) (shutdown func(context.Context) error, err error) {
	if endpoint == "" {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.TraceContext{})
		return func(context.Context) error { return nil }, nil
	}

	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial OTLP endpoint %q: %w", endpoint, err)
	}

	exp, err := otlptrace.New(ctx, otlptracegrpc.NewClient(otlptracegrpc.WithGRPCConn(conn)))
	if err != nil {
		return nil, fmt.Errorf("create OTLP exporter: %w", err)
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(serviceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("build resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sampleRatio))),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return tp.Shutdown, nil
}

// Tracer returns a tracer that respects whatever provider Init installed.
// It's safe to call before Init — you just get no-op spans until the real
// provider is wired.
func Tracer() trace.Tracer {
	return otel.Tracer(tracerName)
}
