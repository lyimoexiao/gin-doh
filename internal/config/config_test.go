package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoad tests configuration loading from file
func TestLoad(t *testing.T) {
	// Test loading the example config (from project root)
	// Skip if running from test directory where config.yaml doesn't exist
	cfg, err := Load("config.yaml")
	if err != nil {
		// Try parent directory
		cfg, err = Load("../config.yaml")
		if err != nil {
			// Try from project root
			cfg, err = Load("../../config.yaml")
			if err != nil {
				t.Skip("config.yaml not found, skipping TestLoad")
			}
		}
	}

	// Verify default values are applied
	if cfg.Server.Listen == "" {
		t.Error("Server.Listen should have default value")
	}

	if cfg.Upstream.Strategy == "" {
		t.Error("Upstream.Strategy should have default value")
	}

	if cfg.Logging.Level == "" {
		t.Error("Logging.Level should have default value")
	}
}

// TestLoadNonExistent tests loading non-existent file
func TestLoadNonExistent(t *testing.T) {
	_, err := Load("non-existent-file.yaml")
	if err == nil {
		t.Error("Load should fail with non-existent file")
	}
}

// TestLoadInvalidYAML tests loading invalid YAML
func TestLoadInvalidYAML(t *testing.T) {
	// Create a temporary file with invalid YAML
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "invalid.yaml")

	content := `
server:
  listen: ":8080"
  invalid yaml content [
    - unclosed
`
	if err := os.WriteFile(tmpFile, []byte(content), 0o600); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	_, err := Load(tmpFile)
	if err == nil {
		t.Error("Load should fail with invalid YAML")
	}
}

// TestSetDefaults tests default value setting
func TestSetDefaults(t *testing.T) {
	cfg := &Config{}
	setDefaults(cfg)

	// Server defaults
	if cfg.Server.Listen != ":443" {
		t.Errorf("Server.Listen default = %s, want :443", cfg.Server.Listen)
	}

	if len(cfg.Server.DNSPaths) != 1 {
		t.Errorf("Server.DNSPaths length = %d, want 1", len(cfg.Server.DNSPaths))
	}

	if cfg.Server.RateLimit.MaxQuerySize != 65535 {
		t.Errorf("Server.RateLimit.MaxQuerySize = %d, want 65535", cfg.Server.RateLimit.MaxQuerySize)
	}

	// Upstream defaults
	if cfg.Upstream.Strategy != "round-robin" {
		t.Errorf("Upstream.Strategy = %s, want round-robin", cfg.Upstream.Strategy)
	}

	if cfg.Upstream.HealthCheck.Interval != 30*time.Second {
		t.Errorf("Upstream.HealthCheck.Interval = %v, want 30s", cfg.Upstream.HealthCheck.Interval)
	}

	if cfg.Upstream.HealthCheck.FailureThreshold != 3 {
		t.Errorf("Upstream.HealthCheck.FailureThreshold = %d, want 3", cfg.Upstream.HealthCheck.FailureThreshold)
	}

	if cfg.Upstream.HealthCheck.RecoveryThreshold != 2 {
		t.Errorf("Upstream.HealthCheck.RecoveryThreshold = %d, want 2", cfg.Upstream.HealthCheck.RecoveryThreshold)
	}

	// Fastest config defaults
	if cfg.Upstream.FastestConfig.WindowSize != 100 {
		t.Errorf("Upstream.FastestConfig.WindowSize = %d, want 100", cfg.Upstream.FastestConfig.WindowSize)
	}

	if cfg.Upstream.FastestConfig.MinSamples != 10 {
		t.Errorf("Upstream.FastestConfig.MinSamples = %d, want 10", cfg.Upstream.FastestConfig.MinSamples)
	}

	if cfg.Upstream.FastestConfig.Cooldown != 60*time.Second {
		t.Errorf("Upstream.FastestConfig.Cooldown = %v, want 60s", cfg.Upstream.FastestConfig.Cooldown)
	}

	// Logging defaults
	if cfg.Logging.Level != "info" {
		t.Errorf("Logging.Level = %s, want info", cfg.Logging.Level)
	}

	if cfg.Logging.Format != "json" {
		t.Errorf("Logging.Format = %s, want json", cfg.Logging.Format)
	}

	if cfg.Logging.Output != "stdout" {
		t.Errorf("Logging.Output = %s, want stdout", cfg.Logging.Output)
	}

	if len(cfg.Logging.Fields) == 0 {
		t.Error("Logging.Fields should have default values")
	}
}

// TestLoadWithCustomValues tests loading config with custom values
func TestLoadWithCustomValues(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "custom.yaml")

	content := `
server:
  listen: ":9090"
  dns_paths:
    - path: /custom-dns
      enabled: true
  rate_limit:
    max_query_size: 4096

upstream:
  strategy: failover
  health_check:
    interval: 60s
    failure_threshold: 5

logging:
  level: debug
  format: console
`
	if err := os.WriteFile(tmpFile, []byte(content), 0o600); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify custom values
	if cfg.Server.Listen != ":9090" {
		t.Errorf("Server.Listen = %s, want :9090", cfg.Server.Listen)
	}

	if len(cfg.Server.DNSPaths) != 1 || cfg.Server.DNSPaths[0].Path != "/custom-dns" {
		t.Errorf("Server.DNSPaths not loaded correctly")
	}

	if cfg.Server.RateLimit.MaxQuerySize != 4096 {
		t.Errorf("Server.RateLimit.MaxQuerySize = %d, want 4096", cfg.Server.RateLimit.MaxQuerySize)
	}

	if cfg.Upstream.Strategy != "failover" {
		t.Errorf("Upstream.Strategy = %s, want failover", cfg.Upstream.Strategy)
	}

	if cfg.Upstream.HealthCheck.Interval != 60*time.Second {
		t.Errorf("Upstream.HealthCheck.Interval = %v, want 60s", cfg.Upstream.HealthCheck.Interval)
	}

	if cfg.Upstream.HealthCheck.FailureThreshold != 5 {
		t.Errorf("Upstream.HealthCheck.FailureThreshold = %d, want 5", cfg.Upstream.HealthCheck.FailureThreshold)
	}

	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %s, want debug", cfg.Logging.Level)
	}

	if cfg.Logging.Format != "console" {
		t.Errorf("Logging.Format = %s, want console", cfg.Logging.Format)
	}
}

// TestUpstreamServerConfig tests upstream server configuration
func TestUpstreamServerConfig(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "upstream.yaml")

	content := `
upstream:
  servers:
    - protocol: doh
      url: https://dns.google/dns-query
      timeout: 10s
    - protocol: dot
      address: 1.1.1.1:853
      server_name: cloudflare-dns.com
      timeout: 5s
    - protocol: udp
      address: 8.8.8.8:53
`
	if err := os.WriteFile(tmpFile, []byte(content), 0o600); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(cfg.Upstream.Servers) != 3 {
		t.Fatalf("Expected 3 upstream servers, got %d", len(cfg.Upstream.Servers))
	}

	// DoH server
	doh := cfg.Upstream.Servers[0]
	if doh.Protocol != "doh" {
		t.Errorf("Protocol = %s, want doh", doh.Protocol)
	}
	if doh.URL != "https://dns.google/dns-query" {
		t.Errorf("URL = %s", doh.URL)
	}

	// DoT server
	dot := cfg.Upstream.Servers[1]
	if dot.Protocol != "dot" {
		t.Errorf("Protocol = %s, want dot", dot.Protocol)
	}
	if dot.ServerName != "cloudflare-dns.com" {
		t.Errorf("ServerName = %s", dot.ServerName)
	}

	// UDP server
	udp := cfg.Upstream.Servers[2]
	if udp.Protocol != "udp" {
		t.Errorf("Protocol = %s, want udp", udp.Protocol)
	}
}

// TestProxyConfig tests proxy configuration
func TestProxyConfig(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "proxy.yaml")

	content := `
upstream:
  proxy:
    enabled: true
    type: socks5
    address: 127.0.0.1:1080
    username: testuser
    password: testpass
`
	if err := os.WriteFile(tmpFile, []byte(content), 0o600); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Upstream.Proxy == nil {
		t.Fatal("Upstream.Proxy is nil")
	}

	if !cfg.Upstream.Proxy.Enabled {
		t.Error("Proxy should be enabled")
	}

	if cfg.Upstream.Proxy.Type != "socks5" {
		t.Errorf("Proxy.Type = %s, want socks5", cfg.Upstream.Proxy.Type)
	}

	if cfg.Upstream.Proxy.Address != "127.0.0.1:1080" {
		t.Errorf("Proxy.Address = %s", cfg.Upstream.Proxy.Address)
	}
}

// TestECHConfig tests ECH configuration
func TestECHConfig(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "ech.yaml")

	content := `
server:
  tls:
    enabled: true
    ech:
      enabled: true
      config_file: /path/to/ech-config.list
      key_file: /path/to/ech-key.pem
      public_name: dns.example.com
      force_encrypted_upstream: true
`
	if err := os.WriteFile(tmpFile, []byte(content), 0o600); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !cfg.Server.TLS.Enabled {
		t.Error("TLS should be enabled")
	}

	if !cfg.Server.TLS.ECH.Enabled {
		t.Error("ECH should be enabled")
	}

	if cfg.Server.TLS.ECH.PublicName != "dns.example.com" {
		t.Errorf("ECH.PublicName = %s", cfg.Server.TLS.ECH.PublicName)
	}

	if !cfg.Server.TLS.ECH.ForceEncryptedUpstream {
		t.Error("ECH.ForceEncryptedUpstream should be true")
	}
}

// TestTrustedProxiesConfig tests trusted proxies configuration
func TestTrustedProxiesConfig(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "trusted.yaml")

	content := `
server:
  trusted_proxies:
    - 127.0.0.1
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
`
	if err := os.WriteFile(tmpFile, []byte(content), 0o600); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(cfg.Server.TrustedProxies) != 4 {
		t.Errorf("Expected 4 trusted proxies, got %d", len(cfg.Server.TrustedProxies))
	}
}
