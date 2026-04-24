package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	content := `
cluster: example-cluster
s3Bucket: test-bucket
s3Region: us-east-1
hubbleAddress: hubble-relay:4245
ciliumSocketPath: /var/run/cilium/cilium.sock

triggers:
  httpErrors:
    enabled: true
    statusCodes: [500, 502]
  drops:
    enabled: true
  dnsFailures:
    enabled: false
    rcodes: [NXDOMAIN]
  latency:
    enabled: true
    thresholdMs: 1000
    windowSize: 50

capture:
  defaultDurationSeconds: 30
  maxSizeBytes: 52428800
  maxConcurrent: 2
  cooldownSeconds: 120

server:
  port: 9090
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(content), 0o644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Cluster != "example-cluster" {
		t.Errorf("Cluster = %s, want example-cluster", cfg.Cluster)
	}
	if cfg.S3Bucket != "test-bucket" {
		t.Errorf("S3Bucket = %s, want test-bucket", cfg.S3Bucket)
	}
	if cfg.S3Region != "us-east-1" {
		t.Errorf("S3Region = %s, want us-east-1", cfg.S3Region)
	}
	if !cfg.Triggers.HTTPErrors.Enabled {
		t.Error("HTTPErrors should be enabled")
	}
	if len(cfg.Triggers.HTTPErrors.StatusCodes) != 2 {
		t.Errorf("expected 2 status codes, got %d", len(cfg.Triggers.HTTPErrors.StatusCodes))
	}
	if cfg.Triggers.DNSFailures.Enabled {
		t.Error("DNSFailures should be disabled")
	}
	if cfg.Capture.DefaultDurationSeconds != 30 {
		t.Errorf("DefaultDurationSeconds = %d, want 30", cfg.Capture.DefaultDurationSeconds)
	}
	if cfg.Capture.MaxConcurrent != 2 {
		t.Errorf("MaxConcurrent = %d, want 2", cfg.Capture.MaxConcurrent)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("Port = %d, want 9090", cfg.Server.Port)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	content := `
cluster: test
s3Bucket: bucket
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(content), 0o644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.HubbleAddress != "hubble-relay.kube-system.svc:4245" {
		t.Errorf("default HubbleAddress = %s", cfg.HubbleAddress)
	}
	if cfg.CiliumSocketPath != "/var/run/cilium/cilium.sock" {
		t.Errorf("default CiliumSocketPath = %s", cfg.CiliumSocketPath)
	}
	if cfg.S3Region != "eu-west-1" {
		t.Errorf("default S3Region = %s", cfg.S3Region)
	}
	if cfg.Capture.DefaultDurationSeconds != 60 {
		t.Errorf("default DefaultDurationSeconds = %d", cfg.Capture.DefaultDurationSeconds)
	}
	if cfg.Capture.MaxSizeBytes != 104857600 {
		t.Errorf("default MaxSizeBytes = %d", cfg.Capture.MaxSizeBytes)
	}
	if cfg.Capture.MaxConcurrent != 3 {
		t.Errorf("default MaxConcurrent = %d", cfg.Capture.MaxConcurrent)
	}
	if cfg.Capture.CooldownSeconds != 300 {
		t.Errorf("default CooldownSeconds = %d", cfg.Capture.CooldownSeconds)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("default Port = %d", cfg.Server.Port)
	}
	if len(cfg.Triggers.HTTPErrors.StatusCodes) != 4 {
		t.Errorf("expected 4 default status codes, got %d", len(cfg.Triggers.HTTPErrors.StatusCodes))
	}
}

func TestLoadConfigFileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte("{{invalid yaml"), 0o644)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestValidateRejectsInvalidConfig(t *testing.T) {
	valid := func() *Config {
		c := &Config{Cluster: "c", S3Bucket: "b"}
		applyDefaults(c)
		return c
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"missing cluster", func(c *Config) { c.Cluster = "" }, "cluster"},
		{"missing bucket", func(c *Config) { c.S3Bucket = "" }, "s3Bucket"},
		{"bad port", func(c *Config) { c.Server.Port = 0 }, "server.port"},
		{"bad port high", func(c *Config) { c.Server.Port = 70000 }, "server.port"},
		{"bad duration", func(c *Config) { c.Capture.DefaultDurationSeconds = -1 }, "defaultDurationSeconds"},
		{"bad max concurrent", func(c *Config) { c.Capture.MaxConcurrent = 0 }, "maxConcurrent"},
		{"bad cooldown", func(c *Config) { c.Capture.CooldownSeconds = -5 }, "cooldownSeconds"},
		{"bad http mode", func(c *Config) { c.Triggers.HTTPErrors.Mode = "bogus" }, "httpErrors.mode"},
		{"bad rate threshold", func(c *Config) {
			c.Triggers.HTTPErrors.Mode = ModeRate
			c.Triggers.HTTPErrors.RateThreshold = 1.5
		}, "rateThreshold"},
		{"bad drops window", func(c *Config) { c.Triggers.Drops.WindowSeconds = 0 }, "drops.windowSeconds"},
		{"bad dns mode", func(c *Config) { c.Triggers.DNSFailures.Mode = "nope" }, "dnsFailures.mode"},
		{"bad latency threshold", func(c *Config) {
			c.Triggers.Latency.Enabled = true
			c.Triggers.Latency.ThresholdMs = 0
		}, "thresholdMs"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected validation error containing %q", tc.want)
			}
			if !contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestValidateAcceptsDefaults(t *testing.T) {
	c := &Config{Cluster: "c", S3Bucket: "b"}
	applyDefaults(c)
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults should validate, got: %v", err)
	}
}

func TestLoadRejectsInvalidConfig(t *testing.T) {
	// Missing required `cluster` field.
	content := "s3Bucket: bucket\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(content), 0o644)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected Load to reject config missing cluster")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
