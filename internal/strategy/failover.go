package strategy

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/lyimoexiao/gin-doh/internal/config"
	"github.com/lyimoexiao/gin-doh/internal/upstream"
)

// FailoverSelector is a failover selector
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

// NewFailoverSelector creates a new failover selector
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

	// Start health check
	if cfg != nil && cfg.Enabled {
		s.healthCheck = newHealthChecker(s, cfg)
		go s.healthCheck.Start()
	}

	return s
}

// Select selects an upstream server (by priority order)
func (s *FailoverSelector) Select(_ context.Context) (upstream.Resolver, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.resolvers) == 0 {
		return nil, ErrNoResolvers
	}

	// Create index list with priorities
	indices := make([]int, len(s.resolvers))
	for i := range indices {
		indices[i] = i
	}

	// Sort by priority
	sort.Slice(indices, func(i, j int) bool {
		return s.priorities[indices[i]] < s.priorities[indices[j]]
	})

	// Select first healthy server
	for _, idx := range indices {
		if s.statuses[idx].healthy {
			return s.resolvers[idx], nil
		}
	}

	// If all servers are unhealthy, return the first (highest priority)
	return s.resolvers[indices[0]], nil
}

// ReportSuccess reports success
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

	// Check if recovered
	if !status.healthy && s.config != nil {
		if status.successCount >= s.config.RecoveryThreshold {
			status.healthy = true
			status.failureCount = 0
		}
	}
}

// ReportSuccessWithLatency reports success with latency (failover mode same as ReportSuccess)
func (s *FailoverSelector) ReportSuccessWithLatency(resolver upstream.Resolver, _ time.Duration) {
	s.ReportSuccess(resolver)
}

// ReportFailure reports failure
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

	// Check if should mark as unhealthy
	if s.config != nil {
		if status.failureCount >= s.config.FailureThreshold {
			status.healthy = false
		}
	}
}

// findResolverIndex finds resolver index
func (s *FailoverSelector) findResolverIndex(resolver upstream.Resolver) int {
	for i, r := range s.resolvers {
		if r == resolver {
			return i
		}
	}
	return -1
}

// GetStatus gets resolver status
func (s *FailoverSelector) GetStatus(idx int) (healthy bool, failureCount int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if idx < 0 || idx >= len(s.statuses) {
		return false, 0
	}

	return s.statuses[idx].healthy, s.statuses[idx].failureCount
}

// Stop stops health check
func (s *FailoverSelector) Stop() {
	if s.healthCheck != nil {
		s.healthCheck.Stop()
	}
}

// healthChecker is a health checker
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
	// Simple health check logic: try to resolve a known domain
	// Actual implementation can be more complex
}
