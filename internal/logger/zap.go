package logger

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger 封装 Zap 日志
type Logger struct {
	*zap.SugaredLogger
	config *Config
}

// Config 日志配置
type Config struct {
	Level  string
	Format string
	Fields []string
}

// New 创建新的日志实例
func New(cfg *Config) (*Logger, error) {
	// 解析日志级别
	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		level = zapcore.InfoLevel
	}

	// 配置编码器
	var encoder zapcore.Encoder
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.MillisDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	if cfg.Format == "console" {
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	// 创建 core
	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(os.Stdout),
		level,
	)

	// 创建 logger
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	return &Logger{
		SugaredLogger: logger.Sugar(),
		config:        cfg,
	}, nil
}

// Sync 刷新日志缓冲
func (l *Logger) Sync() error {
	return l.SugaredLogger.Sync()
}

// IsFieldEnabled 检查字段是否启用
func (l *Logger) IsFieldEnabled(field string) bool {
	for _, f := range l.config.Fields {
		if f == field {
			return true
		}
	}
	return false
}

// DNSRequestFields DNS 请求日志字段
type DNSRequestFields struct {
	Timestamp       string
	ClientIP        string
	Method          string
	Path            string
	QueryName       string
	QueryType       string
	Upstream        string
	UpstreamProtocol string
	ResponseCode    string
	LatencyMs       int64
	Status          int
}

// LogDNSRequest 记录 DNS 请求日志
func (l *Logger) LogDNSRequest(fields *DNSRequestFields) {
	args := make([]interface{}, 0, 22)

	if l.IsFieldEnabled("timestamp") {
		args = append(args, "timestamp", fields.Timestamp)
	}
	if l.IsFieldEnabled("client_ip") {
		args = append(args, "client_ip", fields.ClientIP)
	}
	if l.IsFieldEnabled("method") {
		args = append(args, "method", fields.Method)
	}
	if l.IsFieldEnabled("path") {
		args = append(args, "path", fields.Path)
	}
	if l.IsFieldEnabled("query_name") {
		args = append(args, "query_name", fields.QueryName)
	}
	if l.IsFieldEnabled("query_type") {
		args = append(args, "query_type", fields.QueryType)
	}
	if l.IsFieldEnabled("upstream") {
		args = append(args, "upstream", fields.Upstream)
	}
	if l.IsFieldEnabled("upstream_protocol") {
		args = append(args, "upstream_protocol", fields.UpstreamProtocol)
	}
	if l.IsFieldEnabled("response_code") {
		args = append(args, "response_code", fields.ResponseCode)
	}
	if l.IsFieldEnabled("latency_ms") {
		args = append(args, "latency_ms", fields.LatencyMs)
	}
	if l.IsFieldEnabled("status") {
		args = append(args, "status", fields.Status)
	}

	l.Infow("dns_request", args...)
}

// ParseLevel 解析日志级别
func ParseLevel(level string) zapcore.Level {
	switch strings.ToLower(level) {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}
