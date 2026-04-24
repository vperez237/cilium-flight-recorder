package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	ModeImmediate = "immediate"
	ModeRate      = "rate"
)

type Config struct {
	Cluster          string         `yaml:"cluster"`
	S3Bucket         string         `yaml:"s3Bucket"`
	S3Region         string         `yaml:"s3Region"`
	S3Endpoint       string         `yaml:"s3Endpoint"`
	HubbleAddress    string         `yaml:"hubbleAddress"`
	CiliumSocketPath string         `yaml:"ciliumSocketPath"`
	Triggers         TriggersConfig `yaml:"triggers"`
	Capture          CaptureConfig  `yaml:"capture"`
	Server           ServerConfig   `yaml:"server"`
	Detector         DetectorConfig `yaml:"detector"`
	Upload           UploadConfig   `yaml:"upload"`
	Cilium           CiliumConfig   `yaml:"cilium"`
	Tracing          TracingConfig  `yaml:"tracing"`
}

// DetectorConfig tunes the per-tuple bookkeeping inside AnomalyDetector.
// The janitor sweeps at JanitorIntervalSeconds, evicting entries idle longer
// than IdleEvictAfterSeconds and capping each map at MaxTrackedKeys.
type DetectorConfig struct {
	MaxTrackedKeys         int `yaml:"maxTrackedKeys"`
	IdleEvictAfterSeconds  int `yaml:"idleEvictAfterSeconds"`
	JanitorIntervalSeconds int `yaml:"janitorIntervalSeconds"`
}

// UploadConfig controls the S3 upload retry policy. Each PCAP is attempted
// up to MaxAttempts times with exponential backoff (InitialBackoffMs,
// doubling up to MaxBackoffMs, with ±20% jitter).
type UploadConfig struct {
	MaxAttempts      int `yaml:"maxAttempts"`
	InitialBackoffMs int `yaml:"initialBackoffMs"`
	MaxBackoffMs     int `yaml:"maxBackoffMs"`
}

// CiliumConfig gates calls to the Cilium agent Unix socket. The circuit
// breaker opens after FailureThreshold consecutive failures and stays open
// for CooldownSeconds before admitting a probe, preventing a dead agent
// from stalling every capture for 10s of HTTP timeout.
type CiliumConfig struct {
	CircuitFailureThreshold int `yaml:"circuitFailureThreshold"`
	CircuitCooldownSeconds  int `yaml:"circuitCooldownSeconds"`
}

// TracingConfig wires OpenTelemetry. An empty Endpoint disables tracing
// entirely (a no-op tracer is installed, spans cost ~nothing). SampleRatio
// is only consulted when tracing is enabled.
type TracingConfig struct {
	Endpoint    string  `yaml:"endpoint"`
	SampleRatio float64 `yaml:"sampleRatio"`
}

type TriggersConfig struct {
	HTTPErrors  HTTPErrorsConfig  `yaml:"httpErrors"`
	Drops       DropsConfig       `yaml:"drops"`
	DNSFailures DNSFailuresConfig `yaml:"dnsFailures"`
	Latency     LatencyConfig     `yaml:"latency"`
}

// HTTPErrorsConfig controls the HTTP 5xx trigger.
//
// Mode "immediate": fires on every matching flow (subject to cooldown).
// Mode "rate":      fires when (errors/total) over WindowSeconds exceeds
//                   RateThreshold AND total >= MinEvents. Keyed by dst IP:port.
type HTTPErrorsConfig struct {
	Enabled       bool    `yaml:"enabled"`
	StatusCodes   []int   `yaml:"statusCodes"`
	Mode          string  `yaml:"mode"`
	MinEvents     int     `yaml:"minEvents"`
	RateThreshold float64 `yaml:"rateThreshold"`
	WindowSeconds int     `yaml:"windowSeconds"`
}

// DropsConfig controls the packet-drop trigger.
//
// Mode "immediate": fires on every DROPPED flow.
// Mode "rate":      fires when MinDrops drops are observed for a dst
//                   IP:port within WindowSeconds.
type DropsConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Mode          string `yaml:"mode"`
	MinDrops      int    `yaml:"minDrops"`
	WindowSeconds int    `yaml:"windowSeconds"`
}

// DNSFailuresConfig controls the DNS-failure trigger.
//
// Mode "immediate": fires on every failed DNS response.
// Mode "rate":      fires when (failures/total) over WindowSeconds exceeds
//                   RateThreshold AND total >= MinEvents. Keyed by src IP.
type DNSFailuresConfig struct {
	Enabled       bool     `yaml:"enabled"`
	RCodes        []string `yaml:"rcodes"`
	Mode          string   `yaml:"mode"`
	MinEvents     int      `yaml:"minEvents"`
	RateThreshold float64  `yaml:"rateThreshold"`
	WindowSeconds int      `yaml:"windowSeconds"`
}

type LatencyConfig struct {
	Enabled     bool `yaml:"enabled"`
	ThresholdMs int  `yaml:"thresholdMs"`
	WindowSize  int  `yaml:"windowSize"`
}

type CaptureConfig struct {
	DefaultDurationSeconds int    `yaml:"defaultDurationSeconds"`
	MaxSizeBytes           int64  `yaml:"maxSizeBytes"`
	MaxConcurrent          int    `yaml:"maxConcurrent"`
	CooldownSeconds        int    `yaml:"cooldownSeconds"`
	PcapSourceDir          string `yaml:"pcapSourceDir"`
}

type ServerConfig struct {
	Port int `yaml:"port"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config YAML: %w", err)
	}

	applyDefaults(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return cfg, nil
}

// Validate checks that the configuration is internally consistent and usable.
// It runs after applyDefaults so defaulted fields are included in the checks.
func (c *Config) Validate() error {
	if c.Cluster == "" {
		return fmt.Errorf("cluster must be set")
	}
	if c.S3Bucket == "" {
		return fmt.Errorf("s3Bucket must be set")
	}
	if c.HubbleAddress == "" {
		return fmt.Errorf("hubbleAddress must be set")
	}
	if c.CiliumSocketPath == "" {
		return fmt.Errorf("ciliumSocketPath must be set")
	}

	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be in [1,65535], got %d", c.Server.Port)
	}

	if c.Capture.DefaultDurationSeconds <= 0 {
		return fmt.Errorf("capture.defaultDurationSeconds must be > 0, got %d", c.Capture.DefaultDurationSeconds)
	}
	if c.Capture.MaxSizeBytes <= 0 {
		return fmt.Errorf("capture.maxSizeBytes must be > 0, got %d", c.Capture.MaxSizeBytes)
	}
	if c.Capture.MaxConcurrent <= 0 {
		return fmt.Errorf("capture.maxConcurrent must be > 0, got %d", c.Capture.MaxConcurrent)
	}
	if c.Capture.CooldownSeconds < 0 {
		return fmt.Errorf("capture.cooldownSeconds must be >= 0, got %d", c.Capture.CooldownSeconds)
	}

	if err := validateMode("httpErrors", c.Triggers.HTTPErrors.Mode); err != nil {
		return err
	}
	if c.Triggers.HTTPErrors.WindowSeconds <= 0 {
		return fmt.Errorf("triggers.httpErrors.windowSeconds must be > 0")
	}
	if c.Triggers.HTTPErrors.Mode == ModeRate {
		if c.Triggers.HTTPErrors.RateThreshold < 0 || c.Triggers.HTTPErrors.RateThreshold > 1 {
			return fmt.Errorf("triggers.httpErrors.rateThreshold must be in [0,1], got %v", c.Triggers.HTTPErrors.RateThreshold)
		}
		if c.Triggers.HTTPErrors.MinEvents <= 0 {
			return fmt.Errorf("triggers.httpErrors.minEvents must be > 0 in rate mode")
		}
	}

	if err := validateMode("drops", c.Triggers.Drops.Mode); err != nil {
		return err
	}
	if c.Triggers.Drops.WindowSeconds <= 0 {
		return fmt.Errorf("triggers.drops.windowSeconds must be > 0")
	}
	if c.Triggers.Drops.Mode == ModeRate && c.Triggers.Drops.MinDrops <= 0 {
		return fmt.Errorf("triggers.drops.minDrops must be > 0 in rate mode")
	}

	if err := validateMode("dnsFailures", c.Triggers.DNSFailures.Mode); err != nil {
		return err
	}
	if c.Triggers.DNSFailures.WindowSeconds <= 0 {
		return fmt.Errorf("triggers.dnsFailures.windowSeconds must be > 0")
	}
	if c.Triggers.DNSFailures.Mode == ModeRate {
		if c.Triggers.DNSFailures.RateThreshold < 0 || c.Triggers.DNSFailures.RateThreshold > 1 {
			return fmt.Errorf("triggers.dnsFailures.rateThreshold must be in [0,1], got %v", c.Triggers.DNSFailures.RateThreshold)
		}
		if c.Triggers.DNSFailures.MinEvents <= 0 {
			return fmt.Errorf("triggers.dnsFailures.minEvents must be > 0 in rate mode")
		}
	}

	if c.Triggers.Latency.Enabled {
		if c.Triggers.Latency.ThresholdMs <= 0 {
			return fmt.Errorf("triggers.latency.thresholdMs must be > 0")
		}
		if c.Triggers.Latency.WindowSize <= 0 {
			return fmt.Errorf("triggers.latency.windowSize must be > 0")
		}
	}

	if c.Detector.MaxTrackedKeys <= 0 {
		return fmt.Errorf("detector.maxTrackedKeys must be > 0, got %d", c.Detector.MaxTrackedKeys)
	}
	if c.Detector.IdleEvictAfterSeconds <= 0 {
		return fmt.Errorf("detector.idleEvictAfterSeconds must be > 0, got %d", c.Detector.IdleEvictAfterSeconds)
	}
	if c.Detector.JanitorIntervalSeconds <= 0 {
		return fmt.Errorf("detector.janitorIntervalSeconds must be > 0, got %d", c.Detector.JanitorIntervalSeconds)
	}

	if c.Upload.MaxAttempts <= 0 {
		return fmt.Errorf("upload.maxAttempts must be > 0, got %d", c.Upload.MaxAttempts)
	}
	if c.Upload.InitialBackoffMs <= 0 {
		return fmt.Errorf("upload.initialBackoffMs must be > 0, got %d", c.Upload.InitialBackoffMs)
	}
	if c.Upload.MaxBackoffMs < c.Upload.InitialBackoffMs {
		return fmt.Errorf("upload.maxBackoffMs (%d) must be >= initialBackoffMs (%d)", c.Upload.MaxBackoffMs, c.Upload.InitialBackoffMs)
	}

	if c.Cilium.CircuitFailureThreshold <= 0 {
		return fmt.Errorf("cilium.circuitFailureThreshold must be > 0, got %d", c.Cilium.CircuitFailureThreshold)
	}
	if c.Cilium.CircuitCooldownSeconds <= 0 {
		return fmt.Errorf("cilium.circuitCooldownSeconds must be > 0, got %d", c.Cilium.CircuitCooldownSeconds)
	}

	if c.Tracing.SampleRatio < 0 || c.Tracing.SampleRatio > 1 {
		return fmt.Errorf("tracing.sampleRatio must be in [0,1], got %v", c.Tracing.SampleRatio)
	}

	return nil
}

func validateMode(name, mode string) error {
	if mode != ModeImmediate && mode != ModeRate {
		return fmt.Errorf("triggers.%s.mode must be %q or %q, got %q", name, ModeImmediate, ModeRate, mode)
	}
	return nil
}

func applyDefaults(cfg *Config) {
	if cfg.HubbleAddress == "" {
		cfg.HubbleAddress = "hubble-relay.kube-system.svc:4245"
	}
	if cfg.CiliumSocketPath == "" {
		cfg.CiliumSocketPath = "/var/run/cilium/cilium.sock"
	}
	if cfg.S3Region == "" {
		cfg.S3Region = "eu-west-1"
	}
	if cfg.Capture.DefaultDurationSeconds == 0 {
		cfg.Capture.DefaultDurationSeconds = 60
	}
	if cfg.Capture.MaxSizeBytes == 0 {
		cfg.Capture.MaxSizeBytes = 104857600 // 100MB
	}
	if cfg.Capture.MaxConcurrent == 0 {
		cfg.Capture.MaxConcurrent = 3
	}
	if cfg.Capture.CooldownSeconds == 0 {
		cfg.Capture.CooldownSeconds = 300
	}
	if cfg.Capture.PcapSourceDir == "" {
		cfg.Capture.PcapSourceDir = "/sys/fs/bpf/cilium/recorder"
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}

	// HTTP errors
	if len(cfg.Triggers.HTTPErrors.StatusCodes) == 0 {
		cfg.Triggers.HTTPErrors.StatusCodes = []int{500, 502, 503, 504}
	}
	if cfg.Triggers.HTTPErrors.Mode == "" {
		cfg.Triggers.HTTPErrors.Mode = ModeImmediate
	}
	if cfg.Triggers.HTTPErrors.MinEvents == 0 {
		cfg.Triggers.HTTPErrors.MinEvents = 10
	}
	if cfg.Triggers.HTTPErrors.RateThreshold == 0 {
		cfg.Triggers.HTTPErrors.RateThreshold = 0.05
	}
	if cfg.Triggers.HTTPErrors.WindowSeconds == 0 {
		cfg.Triggers.HTTPErrors.WindowSeconds = 60
	}

	// Drops
	if cfg.Triggers.Drops.Mode == "" {
		cfg.Triggers.Drops.Mode = ModeImmediate
	}
	if cfg.Triggers.Drops.MinDrops == 0 {
		cfg.Triggers.Drops.MinDrops = 5
	}
	if cfg.Triggers.Drops.WindowSeconds == 0 {
		cfg.Triggers.Drops.WindowSeconds = 60
	}

	// DNS failures
	if len(cfg.Triggers.DNSFailures.RCodes) == 0 {
		cfg.Triggers.DNSFailures.RCodes = []string{"NXDOMAIN", "SERVFAIL", "REFUSED"}
	}
	if cfg.Triggers.DNSFailures.Mode == "" {
		cfg.Triggers.DNSFailures.Mode = ModeImmediate
	}
	if cfg.Triggers.DNSFailures.MinEvents == 0 {
		cfg.Triggers.DNSFailures.MinEvents = 10
	}
	if cfg.Triggers.DNSFailures.RateThreshold == 0 {
		cfg.Triggers.DNSFailures.RateThreshold = 0.10
	}
	if cfg.Triggers.DNSFailures.WindowSeconds == 0 {
		cfg.Triggers.DNSFailures.WindowSeconds = 60
	}

	// Latency
	if cfg.Triggers.Latency.ThresholdMs == 0 {
		cfg.Triggers.Latency.ThresholdMs = 2000
	}
	if cfg.Triggers.Latency.WindowSize == 0 {
		cfg.Triggers.Latency.WindowSize = 100
	}

	// Detector janitor
	if cfg.Detector.MaxTrackedKeys == 0 {
		cfg.Detector.MaxTrackedKeys = 10000
	}
	if cfg.Detector.IdleEvictAfterSeconds == 0 {
		cfg.Detector.IdleEvictAfterSeconds = 600 // 10 minutes
	}
	if cfg.Detector.JanitorIntervalSeconds == 0 {
		cfg.Detector.JanitorIntervalSeconds = 60
	}

	// Upload retry
	if cfg.Upload.MaxAttempts == 0 {
		cfg.Upload.MaxAttempts = 5
	}
	if cfg.Upload.InitialBackoffMs == 0 {
		cfg.Upload.InitialBackoffMs = 500
	}
	if cfg.Upload.MaxBackoffMs == 0 {
		cfg.Upload.MaxBackoffMs = 30000
	}

	// Cilium agent circuit breaker
	if cfg.Cilium.CircuitFailureThreshold == 0 {
		cfg.Cilium.CircuitFailureThreshold = 3
	}
	if cfg.Cilium.CircuitCooldownSeconds == 0 {
		cfg.Cilium.CircuitCooldownSeconds = 10
	}

	// Tracing: default sample ratio of 1.0 only matters if tracing is
	// enabled (i.e. Endpoint is non-empty); otherwise it's unused.
	if cfg.Tracing.SampleRatio == 0 {
		cfg.Tracing.SampleRatio = 1.0
	}
}
