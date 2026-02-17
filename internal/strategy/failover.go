package strategy

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/lyimoexiao/gin-doh/internal/config"
	"github.com/lyimoexiao/gin-doh/internal/upstream"
)

// FailoverSelector 主备选择器
type FailoverSelector struct {
	BaseSelector
	config      *config.HealthCheckConfig
	resolvers   []upstream.Resolver
	priorities  []int
	statuses    []*resolverStatus
	healthCheck *healthChecker
	mu          sync.RWMutex
}

type resolverStatus struct {
	failureCount int
	successCount int
	healthy      bool
	lastCheck    time.Time
}

// NewFailoverSelector 创建主备选择器
func NewFailoverSelector(resolvers []upstream.Resolver, priorities []int, cfg *config.HealthCheckConfig) *FailoverSelector {
	statuses := make([]*resolverStatus, len(resolvers))
	for i := range statuses {
		statuses[i] = &resolverStatus{healthy: true}
	}

	s := &FailoverSelector{
		BaseSelector: BaseSelector{
			name:      "failover",
			resolvers: resolvers,
		},
		resolvers:  resolvers,
		priorities: priorities,
		statuses:   statuses,
		config:     cfg,
	}

	// 启动健康检查
	if cfg != nil && cfg.Enabled {
		s.healthCheck = newHealthChecker(s, cfg)
		go s.healthCheck.Start()
	}

	return s
}

// Select 选择一个上游服务器（优先级顺序）
func (s *FailoverSelector) Select(ctx context.Context) (upstream.Resolver, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.resolvers) == 0 {
		return nil, ErrNoResolvers
	}

	// 创建带优先级的索引列表
	indices := make([]int, len(s.resolvers))
	for i := range indices {
		indices[i] = i
	}

	// 按优先级排序
	sort.Slice(indices, func(i, j int) bool {
		return s.priorities[indices[i]] < s.priorities[indices[j]]
	})

	// 选择第一个健康的服务器
	for _, idx := range indices {
		if s.statuses[idx].healthy {
			return s.resolvers[idx], nil
		}
	}

	// 如果所有服务器都不健康，返回第一个（最高优先级）
	return s.resolvers[indices[0]], nil
}

// ReportSuccess 报告成功
func (s *FailoverSelector) ReportSuccess(resolver upstream.Resolver) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.findResolverIndex(resolver)
	if idx < 0 {
		return
	}

	status := s.statuses[idx]
	status.successCount++
	status.lastCheck = time.Now()

	// 检查是否恢复
	if !status.healthy && s.config != nil {
		if status.successCount >= s.config.RecoveryThreshold {
			status.healthy = true
			status.failureCount = 0
		}
	}
}

// ReportSuccessWithLatency 报告成功并记录延迟 (failover 模式与 ReportSuccess 相同)
func (s *FailoverSelector) ReportSuccessWithLatency(resolver upstream.Resolver, latency time.Duration) {
	s.ReportSuccess(resolver)
}

// ReportFailure 报告失败
func (s *FailoverSelector) ReportFailure(resolver upstream.Resolver) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.findResolverIndex(resolver)
	if idx < 0 {
		return
	}

	status := s.statuses[idx]
	status.failureCount++
	status.successCount = 0
	status.lastCheck = time.Now()

	// 检查是否标记为不健康
	if s.config != nil {
		if status.failureCount >= s.config.FailureThreshold {
			status.healthy = false
		}
	}
}

// findResolverIndex 查找解析器索引
func (s *FailoverSelector) findResolverIndex(resolver upstream.Resolver) int {
	for i, r := range s.resolvers {
		if r == resolver {
			return i
		}
	}
	return -1
}

// GetStatus 获取解析器状态
func (s *FailoverSelector) GetStatus(idx int) (healthy bool, failureCount int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if idx < 0 || idx >= len(s.statuses) {
		return false, 0
	}

	return s.statuses[idx].healthy, s.statuses[idx].failureCount
}

// Stop 停止健康检查
func (s *FailoverSelector) Stop() {
	if s.healthCheck != nil {
		s.healthCheck.Stop()
	}
}

// healthChecker 健康检查器
type healthChecker struct {
	selector *FailoverSelector
	config   *config.HealthCheckConfig
	stopCh   chan struct{}
}

func newHealthChecker(selector *FailoverSelector, cfg *config.HealthCheckConfig) *healthChecker {
	return &healthChecker{
		selector: selector,
		config:   cfg,
		stopCh:   make(chan struct{}),
	}
}

func (h *healthChecker) Start() {
	ticker := time.NewTicker(h.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.check()
		case <-h.stopCh:
			return
		}
	}
}

func (h *healthChecker) Stop() {
	close(h.stopCh)
}

func (h *healthChecker) check() {
	// 简单的健康检查逻辑：尝试解析一个已知域名
	// 实际实现可以更复杂
}
