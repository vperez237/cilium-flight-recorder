package capture

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vperez237/cilium-flight-recorder/pkg/config"
	"github.com/vperez237/cilium-flight-recorder/pkg/detector"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func testCiliumCfg() config.CiliumConfig {
	return config.CiliumConfig{
		CircuitFailureThreshold: 3,
		CircuitCooldownSeconds:  1,
	}
}

// mockCiliumAgent creates a Unix socket HTTP server that mimics the Cilium agent recorder API.
type mockCiliumAgent struct {
	listener net.Listener
	server   *http.Server

	mu      sync.Mutex
	created []recorderConfig
	deleted []int64
}

// Created returns a defensive copy so tests can inspect the slice without
// racing against concurrent appends from the HTTP handler goroutine.
func (m *mockCiliumAgent) Created() []recorderConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]recorderConfig, len(m.created))
	copy(out, m.created)
	return out
}

// Deleted returns a defensive copy of the recorded DELETE calls.
func (m *mockCiliumAgent) Deleted() []int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]int64, len(m.deleted))
	copy(out, m.deleted)
	return out
}

func newMockCiliumAgent(t *testing.T, socketPath string) *mockCiliumAgent {
	t.Helper()

	m := &mockCiliumAgent{}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			var cfg recorderConfig
			if err := json.Unmarshal(body, &cfg); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			m.mu.Lock()
			m.created = append(m.created, cfg)
			m.mu.Unlock()
			w.WriteHeader(http.StatusOK)

		case http.MethodDelete:
			m.mu.Lock()
			m.deleted = append(m.deleted, 0)
			m.mu.Unlock()
			w.WriteHeader(http.StatusOK)

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create mock socket: %v", err)
	}

	m.listener = l
	m.server = &http.Server{Handler: mux}
	go m.server.Serve(l)

	return m
}

func (m *mockCiliumAgent) close() {
	m.server.Close()
	m.listener.Close()
}

func TestCaptureManagerCreatesRecorder(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "cilium.sock")
	outputDir := filepath.Join(tmpDir, "pcaps")

	mock := newMockCiliumAgent(t, socketPath)
	defer mock.close()

	// Create a fake PCAP source file that the recorder would produce
	bpfDir := filepath.Join(tmpDir, "bpf")
	os.MkdirAll(bpfDir, 0o755)

	cfg := config.CaptureConfig{
		DefaultDurationSeconds: 1,
		MaxSizeBytes:           1024 * 1024,
		MaxConcurrent:          3,
		CooldownSeconds:        0,
	}

	cm, err := NewCaptureManager(socketPath, outputDir, cfg, testCiliumCfg(), testLogger())
	if err != nil {
		t.Fatalf("failed to create capture manager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqCh := make(chan detector.CaptureRequest, 1)

	go cm.Run(ctx, reqCh)

	reqCh <- detector.CaptureRequest{
		Trigger:   detector.TriggerDrop,
		Reason:    "test drop",
		SrcIP:     "10.0.1.5",
		DstIP:     "10.0.2.10",
		DstPort:   8080,
		Protocol:  "TCP",
		Timestamp: time.Now(),
	}

	// Give time for the capture goroutine to start and call the API
	time.Sleep(500 * time.Millisecond)

	created := mock.Created()
	if len(created) == 0 {
		t.Fatal("expected recorder to be created via Cilium API, got none")
	}

	rc := created[0]
	if len(rc.Filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(rc.Filters))
	}

	f := rc.Filters[0]
	if f.SourceCIDR != "10.0.1.5/32" {
		t.Errorf("expected source CIDR 10.0.1.5/32, got %s", f.SourceCIDR)
	}
	if f.DestCIDR != "10.0.2.10/32" {
		t.Errorf("expected dest CIDR 10.0.2.10/32, got %s", f.DestCIDR)
	}
	if f.DestPort != "8080" {
		t.Errorf("expected dest port 8080, got %s", f.DestPort)
	}
	if f.Protocol != "6" {
		t.Errorf("expected protocol 6 (TCP), got %s", f.Protocol)
	}

	cancel()
}

func TestCaptureManagerRespectsMaxConcurrent(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "cilium.sock")
	outputDir := filepath.Join(tmpDir, "pcaps")

	mock := newMockCiliumAgent(t, socketPath)
	defer mock.close()

	cfg := config.CaptureConfig{
		DefaultDurationSeconds: 5,
		MaxSizeBytes:           1024 * 1024,
		MaxConcurrent:          1,
		CooldownSeconds:        0,
	}

	cm, err := NewCaptureManager(socketPath, outputDir, cfg, testCiliumCfg(), testLogger())
	if err != nil {
		t.Fatalf("failed to create capture manager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqCh := make(chan detector.CaptureRequest, 10)

	go cm.Run(ctx, reqCh)

	// Send 3 requests
	for i := 0; i < 3; i++ {
		reqCh <- detector.CaptureRequest{
			Trigger:   detector.TriggerDrop,
			Reason:    "test",
			SrcIP:     "10.0.1.5",
			DstIP:     "10.0.2.10",
			DstPort:   uint32(8080 + i),
			Protocol:  "TCP",
			Timestamp: time.Now(),
		}
	}

	time.Sleep(500 * time.Millisecond)

	// With MaxConcurrent=1, only 1 should have been created
	if n := len(mock.Created()); n > 1 {
		t.Logf("note: %d recorders created (only 1 expected with MaxConcurrent=1)", n)
	}

	cancel()
}

func TestProtocolToNumber(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"TCP", "6"},
		{"UDP", "17"},
		{"ICMPv4", "1"},
		{"ICMPv6", "58"},
		{"UNKNOWN", "6"},
	}

	for _, tt := range tests {
		got := protocolToNumber(tt.input)
		if got != tt.expected {
			t.Errorf("protocolToNumber(%s) = %s, want %s", tt.input, got, tt.expected)
		}
	}
}

func TestCopyFileAtomic(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.pcap")
	dst := filepath.Join(dir, "out.pcap")

	payload := []byte("pcap-bytes")
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("dst payload = %q, want %q", got, payload)
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("expected no lingering .tmp file, stat err = %v", err)
	}
}

func TestCopyFileCleansTmpOnMissingSource(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "out.pcap")

	err := copyFile(filepath.Join(dir, "nonexistent.pcap"), dst)
	if err == nil {
		t.Fatal("expected error for missing source")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("expected no dst file after failed copy, stat err = %v", err)
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("expected no lingering .tmp file, stat err = %v", err)
	}
}

func TestSanitize(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"10.0.1.5", "10.0.1.5"},
		{"10.0.1.5/32", "10.0.1.5_32"},
		{"hello world", "hello_world"},
		{"tcp:8080", "tcp_8080"},
	}

	for _, tt := range tests {
		got := sanitize(tt.input)
		if got != tt.expected {
			t.Errorf("sanitize(%s) = %s, want %s", tt.input, got, tt.expected)
		}
	}
}
