package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Mock Cilium agent that listens on a Unix socket and simulates the recorder API.
// When a recorder is created, it writes a minimal valid PCAP file after a short delay.

const (
	pcapMagic      = 0xa1b2c3d4
	pcapVersionMaj = 2
	pcapVersionMin = 4
	pcapSnapLen    = 65535
	pcapLinkType   = 1 // Ethernet
)

func main() {
	socketPath := os.Getenv("CILIUM_SOCKET_PATH")
	if socketPath == "" {
		socketPath = "/var/run/cilium/cilium.sock"
	}
	pcapDir := os.Getenv("PCAP_OUTPUT_DIR")
	if pcapDir == "" {
		pcapDir = "/sys/fs/bpf/cilium/recorder"
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	os.MkdirAll(filepath.Dir(socketPath), 0o755)
	os.Remove(socketPath)
	os.MkdirAll(pcapDir, 0o755)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		logger.Error("failed to listen on unix socket", "error", err, "path", socketPath)
		os.Exit(1)
	}
	defer listener.Close()

	// Make socket world-accessible so the flight-recorder container (running
	// as non-root) can connect in the Docker dev environment.
	os.Chmod(socketPath, 0o777)

	logger.Info("mock cilium agent started", "socket", socketPath, "pcap_dir", pcapDir)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger.Info("request received",
			"method", r.Method,
			"path", r.URL.Path,
		)

		if !strings.HasPrefix(r.URL.Path, "/v1/recorder/") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		idStr := strings.TrimPrefix(r.URL.Path, "/v1/recorder/")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid recorder id", http.StatusBadRequest)
			return
		}

		switch r.Method {
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			var cfg map[string]interface{}
			json.Unmarshal(body, &cfg)
			logger.Info("recorder created", "id", id, "config", cfg)

			// Write a dummy PCAP file asynchronously
			go writeDummyPCAP(pcapDir, id, logger)

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

		case http.MethodDelete:
			logger.Info("recorder stopped", "id", id)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	server := &http.Server{Handler: mux}
	if err := server.Serve(listener); err != nil {
		logger.Error("server error", "error", err)
	}
}

func writeDummyPCAP(dir string, id int64, logger *slog.Logger) {
	time.Sleep(500 * time.Millisecond)

	path := filepath.Join(dir, fmt.Sprintf("%d.pcap", id))
	f, err := os.Create(path)
	if err != nil {
		logger.Error("failed to create PCAP file", "error", err, "path", path)
		return
	}
	defer f.Close()

	// PCAP global header
	binary.Write(f, binary.LittleEndian, uint32(pcapMagic))
	binary.Write(f, binary.LittleEndian, uint16(pcapVersionMaj))
	binary.Write(f, binary.LittleEndian, uint16(pcapVersionMin))
	binary.Write(f, binary.LittleEndian, int32(0))  // thiszone
	binary.Write(f, binary.LittleEndian, uint32(0))  // sigfigs
	binary.Write(f, binary.LittleEndian, uint32(pcapSnapLen))
	binary.Write(f, binary.LittleEndian, uint32(pcapLinkType))

	// Write a few dummy Ethernet frames
	for i := 0; i < 5; i++ {
		pkt := makeDummyEthernetFrame(i)
		ts := time.Now()
		// Packet record header
		binary.Write(f, binary.LittleEndian, uint32(ts.Unix()))
		binary.Write(f, binary.LittleEndian, uint32(ts.Nanosecond()/1000))
		binary.Write(f, binary.LittleEndian, uint32(len(pkt)))
		binary.Write(f, binary.LittleEndian, uint32(len(pkt)))
		f.Write(pkt)
		time.Sleep(100 * time.Millisecond)
	}

	logger.Info("dummy PCAP written", "path", path, "packets", 5)
}

func makeDummyEthernetFrame(seq int) []byte {
	frame := make([]byte, 74)
	// Dst MAC
	frame[0], frame[1], frame[2], frame[3], frame[4], frame[5] = 0x00, 0x11, 0x22, 0x33, 0x44, 0x55
	// Src MAC
	frame[6], frame[7], frame[8], frame[9], frame[10], frame[11] = 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb
	// EtherType: IPv4
	frame[12], frame[13] = 0x08, 0x00
	// Minimal IPv4 header (20 bytes)
	frame[14] = 0x45 // version + IHL
	frame[16], frame[17] = 0x00, 0x3c // total length = 60
	frame[22] = 64   // TTL
	frame[23] = 6    // protocol: TCP
	// Src IP: 10.0.1.{seq+1}
	frame[26], frame[27], frame[28], frame[29] = 10, 0, 1, byte(seq+1)
	// Dst IP: 10.0.2.100
	frame[30], frame[31], frame[32], frame[33] = 10, 0, 2, 100
	// TCP header starts at offset 34 (20 bytes)
	frame[34], frame[35] = 0xc0, 0x00 // src port 49152
	frame[36], frame[37] = 0x1f, 0x90 // dst port 8080
	frame[46] = 0x50 // data offset
	frame[47] = 0x02 // SYN flag
	return frame
}
