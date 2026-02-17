package strategy

import (
	"context"
	"sync"
	"time"

	"github.com/lyimoexiao/gin-doh/internal/config"
	"github.com/lyimoexiao/gin-doh/internal/upstream"
)

// FastestSelector 最快响应选择器
type FastestSelector struct {
	BaseSelector
	config   *config.FastestConfig
	resolvers []upstream.Resolver
	stats    []*resolverStats
	mu       sync.RWMutex
}

type resolverStats struct {
	samples    []time.Duration
	totalCount int
	avgLatency time.Duration
	lastSelect time.Time
}

// NewFastestSelector 创建最快响应选择器
func NewFastestSelector(resolvers []upstream.Resolver, cfg *config.FastestConfig) *FastestSelector {
	stats := make([]*resolverStats, len(resolvers))
	for i := range stats {
		stats[i] = &resolverStats{
			samples: make([]time.Duration, 0, cfg.WindowSize),
		}
	}

	return &FastestSelector{
		BaseSelector: BaseSelector{
			name:      "fastest",
			resolvers: resolvers,
		},
		resolvers: resolvers,
		config:    cfg,
		stats:     stats,
	}
}

// Select 选择一个上游服务器（最快响应）
func (s *FastestSelector) Select(ctx context.Context) (upstream.Resolver, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.resolvers) == 0 {
		return nil, ErrNoResolvers
	}

	// 找到最快的解析器
	bestIdx := 0
	bestLatency := time.Duration(1<<63 - 1)
	validCount := 0

	for i, stat := range s.stats {
		// 检查冷却时间
		if !stat.lastSelect.IsZero() && time.Since(stat.lastSelect) < s.config.Cooldown {
			continue
		}

		// 检查最小样本数
		if len(stat.samples) >= s.config.MinSamples {
			validCount++
			if stat.avgLatency < bestLatency {
				bestLatency = stat.avgLatency
				bestIdx = i
			}
		}
	}

	// 如果没有足够的样本，使用轮询
	if validCount == 0 {
		// 选择样本最少的解析器（给新解析器机会）
		minSamples := len(s.stats[0].samples)
		for i, stat := range s.stats {
			if len(stat.samples) < minSamples {
				minSamples = len(stat.samples)
				bestIdx = i
			}
		}
	}

	s.stats[bestIdx].lastSelect = time.Now()
	return s.resolvers[bestIdx], nil
}

// ReportSuccess 报告成功并更新统计
func (s *FastestSelector) ReportSuccess(resolver upstream.Resolver) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.findResolverIndex(resolver)
	if idx < 0 {
		return
	}

	// 记录延迟（需要在调用前记录开始时间，这里简化处理）
	// 实际实现中应该传入延迟值
}

// ReportSuccessWithLatency 报告成功并记录延迟
func (s *FastestSelector) ReportSuccessWithLatency(resolver upstream.Resolver, latency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.findResolverIndex(resolver)
	if idx < 0 {
		return
	}

	stat := s.stats[idx]

	// 添加到滑动窗口
	stat.samples = append(stat.samples, latency)
	if len(stat.samples) > s.config.WindowSize {
		stat.samples = stat.samples[1:]
	}

	// 计算平均延迟
	stat.totalCount++
	var total time.Duration
	for _, d := range stat.samples {
		total += d
	}
	stat.avgLatency = total / time.Duration(len(stat.samples))
}

// ReportFailure 报告失败
func (s *FastestSelector) ReportFailure(resolver upstream.Resolver) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.findResolverIndex(resolver)
	if idx < 0 {
		return
	}

	// 失败时增加一个较大的延迟值作为惩罚
	stat := s.stats[idx]
	penalty := time.Second * 10 // 惩罚值
	stat.samples = append(stat.samples, penalty)
	if len(stat.samples) > s.config.WindowSize {
		stat.samples = stat.samples[1:]
	}
}

// findResolverIndex 查找解析器索引
func (s *FastestSelector) findResolverIndex(resolver upstream.Resolver) int {
	for i, r := range s.resolvers {
		if r == resolver {
			return i
		}
	}
	return -1
}

// GetStats 获取解析器统计信息
func (s *FastestSelector) GetStats() []ResolverStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]ResolverStats, len(s.stats))
	for i, stat := range s.stats {
		result[i] = ResolverStats{
			AvgLatency: stat.avgLatency,
			Samples:    len(stat.samples),
			TotalCount: stat.totalCount,
		}
	}
	return result
}

// ResolverStats 解析器统计信息
type ResolverStats struct {
	AvgLatency time.Duration
	Samples    int
	TotalCount int
}
