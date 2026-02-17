package upstream

import (
	"context"
	"time"

	"github.com/lyimoexiao/gin-doh/internal/config"
	"github.com/lyimoexiao/gin-doh/internal/ech"
	"github.com/lyimoexiao/gin-doh/internal/proxy"
)

// Factory 解析器工厂
type Factory struct {
	globalProxy *proxy.Manager
}

// NewFactory 创建解析器工厂
func NewFactory(globalProxy *proxy.Manager) *Factory {
	return &Factory{
		globalProxy: globalProxy,
	}
}

// CreateResolver 创建解析器
func (f *Factory) CreateResolver(cfg *config.UpstreamServer) (Resolver, error) {
	return f.CreateResolverWithECH(cfg, nil)
}

// CreateResolverWithECH 创建解析器 (支持 ECH 配置)
func (f *Factory) CreateResolverWithECH(cfg *config.UpstreamServer, globalECHConfig *ech.ClientECHConfig) (Resolver, error) {
	// 确定使用的代理
	var proxyMgr *proxy.Manager
	var err error

	if cfg.Proxy != nil && cfg.Proxy.Enabled {
		// 使用服务器级代理
		proxyMgr, err = proxy.NewManager(cfg.Proxy)
		if err != nil {
			return nil, err
		}
	} else if f.globalProxy != nil && f.globalProxy.Enabled() {
		// 使用全局代理
		proxyMgr = f.globalProxy
	}

	// 设置默认超时
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	// 准备 ECH 配置
	var echConfig *ech.ClientECHConfig
	if cfg.ECH != nil && cfg.ECH.Enabled {
		// 使用服务器级 ECH 配置
		echConfig = ech.NewClientECHConfig()
		if cfg.ECH.ConfigList != "" {
			// 尝试作为 Base64 加载
			if err := echConfig.LoadConfigListFromBase64(cfg.ECH.ConfigList); err != nil {
				// 尝试作为文件路径加载
				if err := echConfig.LoadConfigListFromFile(cfg.ECH.ConfigList); err != nil {
					return nil, err
				}
			}
		}
	} else if globalECHConfig != nil && len(globalECHConfig.ConfigList) > 0 {
		// 使用全局 ECH 配置
		echConfig = globalECHConfig
	}

	// 根据协议创建解析器
	switch cfg.Protocol {
	case "udp":
		return NewUDPResolver(cfg.Address, timeout), nil
	case "tcp":
		return NewTCPResolver(cfg.Address, timeout), nil
	case "doh":
		if echConfig != nil {
			return NewDoHResolver(cfg.URL, timeout, proxyMgr, WithECH(echConfig)), nil
		}
		return NewDoHResolver(cfg.URL, timeout, proxyMgr), nil
	case "dot":
		return NewDoTResolver(cfg.Address, cfg.ServerName, timeout, proxyMgr), nil
	default:
		return nil, ErrUnsupportedProtocol
	}
}

// ErrUnsupportedProtocol 不支持的协议错误
var ErrUnsupportedProtocol = &ProtocolError{}

// ProtocolError 协议错误
type ProtocolError struct {
	Protocol string
}

func (e *ProtocolError) Error() string {
	return "unsupported protocol: " + e.Protocol
}

// ResolverWithStats 带统计的解析器
type ResolverWithStats struct {
	Resolver
	stats ResolverStats
}

// NewResolverWithStats 创建带统计的解析器
func NewResolverWithStats(resolver Resolver) *ResolverWithStats {
	return &ResolverWithStats{
		Resolver: resolver,
	}
}

// Resolve 执行 DNS 解析并更新统计
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

// Stats 返回统计信息
func (r *ResolverWithStats) Stats() ResolverStats {
	return r.stats
}