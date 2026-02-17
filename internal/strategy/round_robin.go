package strategy

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/lyimoexiao/gin-doh/internal/upstream"
)

// RoundRobinSelector is a round-robin selector
type RoundRobinSelector struct {
	BaseSelector
	current uint64
}

// NewRoundRobinSelector creates a new round-robin selector
func NewRoundRobinSelector(resolvers []upstream.Resolver) *RoundRobinSelector {
	return &RoundRobinSelector{
		BaseSelector: BaseSelector{
			name:      "round-robin",
			resolvers: resolvers,
		},
	}
}

// Select selects an upstream server (round-robin)
func (s *RoundRobinSelector) Select(_ context.Context) (upstream.Resolver, error) {
	if len(s.resolvers) == 0 {
		return nil, ErrNoResolvers
	}

	idx := atomic.AddUint64(&s.current, 1) - 1
	return s.resolvers[idx%uint64(len(s.resolvers))], nil
}

// ReportSuccess reports success (round-robin doesn't need this)
func (s *RoundRobinSelector) ReportSuccess(_ upstream.Resolver) {}

// ReportSuccessWithLatency reports success with latency (round-robin doesn't need this)
func (s *RoundRobinSelector) ReportSuccessWithLatency(_ upstream.Resolver, _ time.Duration) {}

// ReportFailure reports failure (round-robin doesn't need this)
func (s *RoundRobinSelector) ReportFailure(_ upstream.Resolver) {}

// ErrNoResolvers indicates no resolvers available
var ErrNoResolvers = &NoResolversError{}

// NoResolversError is no resolvers error
type NoResolversError struct{}

func (e *NoResolversError) Error() string {
	return "no resolvers available"
}
