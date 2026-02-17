package strategy

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/lyimoexiao/gin-doh/internal/upstream"
)

// RoundRobinSelector 轮询选择器
type RoundRobinSelector struct {
	BaseSelector
	current uint64
}

// NewRoundRobinSelector 创建轮询选择器
func NewRoundRobinSelector(resolvers []upstream.Resolver) *RoundRobinSelector {
	return &RoundRobinSelector{
		BaseSelector: BaseSelector{
			name:      "round-robin",
			resolvers: resolvers,
		},
	}
}

// Select 选择一个上游服务器（轮询）
func (s *RoundRobinSelector) Select(ctx context.Context) (upstream.Resolver, error) {
	if len(s.resolvers) == 0 {
		return nil, ErrNoResolvers
	}

	idx := atomic.AddUint64(&s.current, 1) - 1
	return s.resolvers[idx%uint64(len(s.resolvers))], nil
}

// ReportSuccess 报告成功（轮询策略不需要）
func (s *RoundRobinSelector) ReportSuccess(resolver upstream.Resolver) {}

// ReportSuccessWithLatency 报告成功并记录延迟（轮询策略不需要）
func (s *RoundRobinSelector) ReportSuccessWithLatency(resolver upstream.Resolver, latency time.Duration) {}

// ReportFailure 报告失败（轮询策略不需要）
func (s *RoundRobinSelector) ReportFailure(resolver upstream.Resolver) {}

// ErrNoResolvers 没有可用的解析器
var ErrNoResolvers = &NoResolversError{}

// NoResolversError 没有解析器错误
type NoResolversError struct{}

func (e *NoResolversError) Error() string {
	return "no resolvers available"
}
