package strategy

import (
	"context"
	"sync"
	"time"

	"github.com/lyimoexiao/gin-doh/internal/config"
	"github.com/lyimoexiao/gin-doh/internal/upstream"
)

// FastestSelector is a fastest response selector
type FastestSelector struct {
	BaseSelector
	config    *config.FastestConfig
	resolvers []upstream.Resolver
	stats     []*resolverStats
	mu        sync.RWMutex
}

type resolverStats struct {
	samples    []time.Duration
	totalCount int
	avgLatency time.Duration
	lastSelect time.Time
}

// NewFastestSelector creates a new fastest selector
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

// Select selects an upstream server (fastest response)
func (s *FastestSelector) Select(_ context.Context) (upstream.Resolver, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.resolvers) == 0 {
		return nil, ErrNoResolvers
	}

	// Find fastest resolver
	bestIdx := 0
	bestLatency := time.Duration(1<<63 - 1)
	validCount := 0

	for i, stat := range s.stats {
		// Check cooldown
		if !stat.lastSelect.IsZero() && time.Since(stat.lastSelect) < s.config.Cooldown {
			continue
		}

		// Check minimum samples
		if len(stat.samples) >= s.config.MinSamples {
			validCount++
			if stat.avgLatency < bestLatency {
				bestLatency = stat.avgLatency
				bestIdx = i
			}
		}
	}

	// If not enough samples, use round robin
	if validCount == 0 {
		// Select resolver with least samples (give new resolvers a chance)
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

// ReportSuccess reports success (fastest mode uses ReportSuccessWithLatency)
func (s *FastestSelector) ReportSuccess(_ upstream.Resolver) {
	// Fastest mode requires latency tracking, use ReportSuccessWithLatency
}

// ReportSuccessWithLatency reports success with latency
func (s *FastestSelector) ReportSuccessWithLatency(resolver upstream.Resolver, latency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.findResolverIndex(resolver)
	if idx < 0 {
		return
	}

	stat := s.stats[idx]

	// Add to sliding window
	stat.samples = append(stat.samples, latency)
	if len(stat.samples) > s.config.WindowSize {
		stat.samples = stat.samples[1:]
	}

	// Calculate average latency
	stat.totalCount++
	var total time.Duration
	for _, d := range stat.samples {
		total += d
	}
	stat.avgLatency = total / time.Duration(len(stat.samples))
}

// ReportFailure reports failure
func (s *FastestSelector) ReportFailure(resolver upstream.Resolver) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.findResolverIndex(resolver)
	if idx < 0 {
		return
	}

	// Add a large latency value as penalty on failure
	stat := s.stats[idx]
	penalty := time.Second * 10
	stat.samples = append(stat.samples, penalty)
	if len(stat.samples) > s.config.WindowSize {
		stat.samples = stat.samples[1:]
	}
}

// findResolverIndex finds resolver index
func (s *FastestSelector) findResolverIndex(resolver upstream.Resolver) int {
	for i, r := range s.resolvers {
		if r == resolver {
			return i
		}
	}
	return -1
}

// GetStats gets resolver statistics
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

// ResolverStats contains resolver statistics
type ResolverStats struct {
	AvgLatency time.Duration
	Samples    int
	TotalCount int
}
