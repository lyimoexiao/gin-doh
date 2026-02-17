package upstream

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lyimoexiao/gin-doh/internal/config"
	"github.com/lyimoexiao/gin-doh/internal/ech"
	"github.com/lyimoexiao/gin-doh/internal/proxy"
)

// Factory creates resolvers
type Factory struct {
	globalProxy        *proxy.Manager
	forceEncrypted     bool
	echConfigAvailable bool
}

// FactoryOption is a factory option
type FactoryOption func(*Factory)

// WithForceEncrypted sets force encrypted upstream
func WithForceEncrypted(force bool) FactoryOption {
	return func(f *Factory) {
		f.forceEncrypted = force
	}
}

// WithECHAvailable sets ECH config availability
func WithECHAvailable(available bool) FactoryOption {
	return func(f *Factory) {
		f.echConfigAvailable = available
	}
}

// NewFactory creates a new resolver factory
func NewFactory(globalProxy *proxy.Manager, opts ...FactoryOption) *Factory {
	f := &Factory{
		globalProxy: globalProxy,
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// CreateResolver creates a resolver
func (f *Factory) CreateResolver(cfg *config.UpstreamServer) (Resolver, error) {
	return f.CreateResolverWithECH(cfg, nil)
}

// CreateResolverWithECH creates a resolver with ECH config
func (f *Factory) CreateResolverWithECH(cfg *config.UpstreamServer, globalECHConfig *ech.ClientECHConfig) (Resolver, error) {
	// Check if encrypted upstream is required
	if err := f.validateEncryptedProtocol(cfg); err != nil {
		return nil, err
	}

	// Setup proxy manager
	proxyMgr, err := f.setupProxy(cfg)
	if err != nil {
		return nil, err
	}

	// Setup timeout
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	// Setup ECH config
	echConfig, echEnabled := f.setupECHConfig(cfg, globalECHConfig)

	// Create resolver based on protocol
	return f.createResolverByProtocol(cfg, timeout, proxyMgr, echConfig, echEnabled)
}

// validateEncryptedProtocol validates that the protocol is allowed
func (f *Factory) validateEncryptedProtocol(cfg *config.UpstreamServer) error {
	if f.forceEncrypted || f.echConfigAvailable {
		if cfg.Protocol == "udp" || cfg.Protocol == "tcp" {
			return fmt.Errorf("ECH enabled: protocol %s is not allowed, only encrypted protocols (doh, dot) are supported", cfg.Protocol)
		}
	}
	return nil
}

// setupProxy sets up the proxy manager for the resolver
func (f *Factory) setupProxy(cfg *config.UpstreamServer) (*proxy.Manager, error) {
	if cfg.Proxy != nil && cfg.Proxy.Enabled {
		return proxy.NewManager(cfg.Proxy)
	}
	if f.globalProxy != nil && f.globalProxy.Enabled() {
		return f.globalProxy, nil
	}
	return nil, nil
}

// setupECHConfig sets up ECH configuration
func (f *Factory) setupECHConfig(cfg *config.UpstreamServer, globalECHConfig *ech.ClientECHConfig) (*ech.ClientECHConfig, bool) {
	// Try server-level ECH config first
	if cfg.ECH != nil && cfg.ECH.Enabled {
		echConfig := ech.NewClientECHConfig()
		if cfg.ECH.ConfigList != "" {
			// Try loading as Base64 first
			if err := echConfig.LoadConfigListFromBase64(cfg.ECH.ConfigList); err != nil {
				// Try loading as file path
				if err := echConfig.LoadConfigListFromFile(cfg.ECH.ConfigList); err != nil {
					return nil, false
				}
			}
		}
		return echConfig, true
	}

	// Fall back to global ECH config
	if globalECHConfig != nil && len(globalECHConfig.ConfigList) > 0 {
		return globalECHConfig, true
	}

	return nil, false
}

// createResolverByProtocol creates a resolver based on protocol type
func (f *Factory) createResolverByProtocol(cfg *config.UpstreamServer, timeout time.Duration, proxyMgr *proxy.Manager, echConfig *ech.ClientECHConfig, echEnabled bool) (Resolver, error) {
	switch cfg.Protocol {
	case "udp":
		return NewUDPResolver(cfg.Address, timeout), nil
	case "tcp":
		return NewTCPResolver(cfg.Address, timeout), nil
	case "doh":
		if echEnabled && echConfig != nil {
			return NewDoHResolver(cfg.URL, timeout, proxyMgr, WithECH(echConfig)), nil
		}
		return NewDoHResolver(cfg.URL, timeout, proxyMgr), nil
	case "dot":
		return NewDoTResolver(cfg.Address, cfg.ServerName, timeout, proxyMgr), nil
	default:
		return nil, ErrUnsupportedProtocol
	}
}

// Error definitions
var (
	ErrUnsupportedProtocol  = &ProtocolError{}
	ErrUnencryptedForbidden = errors.New("ECH mode requires encrypted upstream (doh or dot)")
)

// ProtocolError is a protocol error
type ProtocolError struct {
	Protocol string
}

func (e *ProtocolError) Error() string {
	return "unsupported protocol: " + e.Protocol
}

// ResolverWithStats is a resolver with statistics
type ResolverWithStats struct {
	Resolver
	stats ResolverStats
}

// NewResolverWithStats creates a resolver with statistics
func NewResolverWithStats(resolver Resolver) *ResolverWithStats {
	return &ResolverWithStats{
		Resolver: resolver,
	}
}

// Resolve performs DNS resolution and updates statistics
func (r *ResolverWithStats) Resolve(ctx context.Context, query []byte) ([]byte, error) {
	start := time.Now()
	r.stats.TotalRequests++

	resp, err := r.Resolver.Resolve(ctx, query)
	if err != nil {
		r.stats.FailedRequests++
		return nil, err
	}

	r.stats.SuccessRequests++
	latency := time.Since(start)
	r.stats.TotalLatency += latency
	r.stats.AvgLatency = time.Duration(int64(r.stats.TotalLatency) / r.stats.SuccessRequests)

	return resp, nil
}

// Stats returns statistics
func (r *ResolverWithStats) Stats() ResolverStats {
	return r.stats
}
