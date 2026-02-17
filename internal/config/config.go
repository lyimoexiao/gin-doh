package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 主配置结构
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Upstream UpstreamConfig `yaml:"upstream"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Listen    string       `yaml:"listen"`
	TLS       TLSConfig    `yaml:"tls"`
	HTTP2     HTTP2Config  `yaml:"http2"`
	HTTP3     HTTP3Config  `yaml:"http3"`
	DNSPaths  []DNSPath    `yaml:"dns_paths"`
	RateLimit RateLimitCfg `yaml:"rate_limit"`
}

// TLSConfig TLS 配置
type TLSConfig struct {
	Enabled  bool        `yaml:"enabled"`
	CertFile string      `yaml:"cert_file"`
	KeyFile  string      `yaml:"key_file"`
	ECH      ECHConfig   `yaml:"ech"` // ECH 配置
}

// ECHConfig ECH (Encrypted Client Hello) 配置
type ECHConfig struct {
	// 服务端 ECH 配置
	Enabled       bool   `yaml:"enabled"`          // 是否启用 ECH
	ConfigFile    string `yaml:"config_file"`      // ECH 配置文件路径 (包含公钥配置列表)
	KeyFile       string `yaml:"key_file"`         // ECH 私钥文件路径
	PublicName    string `yaml:"public_name"`      // 公共名称 (用于 ECH)
	RetryConfigFile string `yaml:"retry_config_file"` // 重试配置文件路径

	// 客户端 ECH 配置 (用于上游 DoH 连接)
	ConfigListFile string `yaml:"config_list_file"` // ECH 配置列表文件路径

	// 强制使用加密上游 (当 ECH 启用时，禁止回落到 UDP/TCP)
	ForceEncryptedUpstream bool `yaml:"force_encrypted_upstream"` // 强制使用加密上游
}

// HTTP2Config HTTP/2 配置
type HTTP2Config struct {
	Enabled bool `yaml:"enabled"`
}

// HTTP3Config HTTP/3 配置
type HTTP3Config struct {
	Enabled bool `yaml:"enabled"`
}

// DNSPath DNS 查询路径配置
type DNSPath struct {
	Path    string `yaml:"path"`
	Enabled bool   `yaml:"enabled"`
}

// RateLimitCfg 速率限制配置
type RateLimitCfg struct {
	Enabled      bool `yaml:"enabled"`
	RequestsPer  int  `yaml:"requests_per"`
	Burst        int  `yaml:"burst"`
	MaxQuerySize int  `yaml:"max_query_size"`
}

// UpstreamConfig 上游配置
type UpstreamConfig struct {
	Strategy      string             `yaml:"strategy"`
	HealthCheck   HealthCheckConfig  `yaml:"health_check"`
	FastestConfig FastestConfig      `yaml:"fastest_config"`
	Proxy         *ProxyConfig       `yaml:"proxy"`
	Servers       []UpstreamServer   `yaml:"servers"`
}

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Interval          time.Duration `yaml:"interval"`
	FailureThreshold  int           `yaml:"failure_threshold"`
	RecoveryThreshold int           `yaml:"recovery_threshold"`
}

// FastestConfig 最快响应模式配置
type FastestConfig struct {
	WindowSize int           `yaml:"window_size"`
	MinSamples int           `yaml:"min_samples"`
	Cooldown   time.Duration `yaml:"cooldown"`
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Type     string `yaml:"type"`     // http 或 socks5
	Address  string `yaml:"address"`  // host:port
	Username string `yaml:"username"` // 可选
	Password string `yaml:"password"` // 可选
}

// UpstreamServer 上游服务器配置
type UpstreamServer struct {
	Protocol   string        `yaml:"protocol"`    // udp, tcp, doh, dot
	Address    string        `yaml:"address"`     // 用于 udp, tcp, dot
	URL        string        `yaml:"url"`         // 用于 doh
	ServerName string        `yaml:"server_name"` // 用于 dot
	Timeout    time.Duration `yaml:"timeout"`
	Priority   int           `yaml:"priority"` // 用于 failover 模式
	Proxy      *ProxyConfig  `yaml:"proxy"`    // 服务器级代理配置
	ECH        *ClientECHConfig `yaml:"ech"` // ECH 客户端配置
}

// ClientECHConfig 客户端 ECH 配置 (用于连接上游服务器)
type ClientECHConfig struct {
	Enabled     bool   `yaml:"enabled"`       // 是否启用 ECH
	ConfigList  string `yaml:"config_list"`   // ECH 配置列表 (Base64 编码或文件路径)
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Level  string   `yaml:"level"`  // debug, info, warn, error
	Format string   `yaml:"format"` // json 或 console
	Output string   `yaml:"output"` // stdout
	Fields []string `yaml:"fields"` // 要输出的字段
}

// Load 从文件加载配置
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// 设置默认值
	setDefaults(&cfg)

	return &cfg, nil
}

// setDefaults 设置默认值
func setDefaults(cfg *Config) {
	// 服务器默认值
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":443"
	}

	if len(cfg.Server.DNSPaths) == 0 {
		cfg.Server.DNSPaths = []DNSPath{
			{Path: "/dns-query", Enabled: true},
		}
	}

	if cfg.Server.RateLimit.MaxQuerySize == 0 {
		cfg.Server.RateLimit.MaxQuerySize = 65535 // DNS 最大消息大小
	}

	// 上游默认值
	if cfg.Upstream.Strategy == "" {
		cfg.Upstream.Strategy = "round-robin"
	}

	if cfg.Upstream.HealthCheck.Interval == 0 {
		cfg.Upstream.HealthCheck.Interval = 30 * time.Second
	}
	if cfg.Upstream.HealthCheck.FailureThreshold == 0 {
		cfg.Upstream.HealthCheck.FailureThreshold = 3
	}
	if cfg.Upstream.HealthCheck.RecoveryThreshold == 0 {
		cfg.Upstream.HealthCheck.RecoveryThreshold = 2
	}

	if cfg.Upstream.FastestConfig.WindowSize == 0 {
		cfg.Upstream.FastestConfig.WindowSize = 100
	}
	if cfg.Upstream.FastestConfig.MinSamples == 0 {
		cfg.Upstream.FastestConfig.MinSamples = 10
	}
	if cfg.Upstream.FastestConfig.Cooldown == 0 {
		cfg.Upstream.FastestConfig.Cooldown = 60 * time.Second
	}

	// 日志默认值
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}
	if cfg.Logging.Output == "" {
		cfg.Logging.Output = "stdout"
	}
	if len(cfg.Logging.Fields) == 0 {
		cfg.Logging.Fields = []string{
			"timestamp", "client_ip", "method", "path",
			"query_name", "query_type", "upstream",
			"upstream_protocol", "response_code",
			"latency_ms", "status",
		}
	}
}
