package strategy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lyimoexiao/gin-doh/internal/config"
	"github.com/lyimoexiao/gin-doh/internal/upstream"
)

// mockResolver is a mock resolver for testing
type mockResolver struct {
	protocol string
	address  string
	latency  time.Duration
	err      error
}

func (m *mockResolver) Resolve(_ context.Context, _ []byte) ([]byte, error) {
	if m.latency > 0 {
		time.Sleep(m.latency)
	}
	if m.err != nil {
		return nil, m.err
	}
	return []byte("mock response"), nil
}

func (m *mockResolver) Protocol() string {
	return m.protocol
}

func (m *mockResolver) Address() string {
	return m.address
}

func (m *mockResolver) String() string {
	return m.protocol + "://" + m.address
}

// TestRoundRobinSelector tests round-robin selection
func TestRoundRobinSelector(t *testing.T) {
	resolvers := []upstream.Resolver{
		&mockResolver{protocol: "udp", address: "8.8.8.8:53"},
		&mockResolver{protocol: "udp", address: "8.8.4.4:53"},
		&mockResolver{protocol: "udp", address: "1.1.1.1:53"},
	}

	selector := NewRoundRobinSelector(resolvers)

	// Test name
	if selector.Name() != "round-robin" {
		t.Errorf("Name = %s, want round-robin", selector.Name())
	}

	// Test round-robin selection
	ctx := context.Background()

	// Should cycle through all resolvers
	selected := make(map[string]int)
	for i := 0; i < 6; i++ {
		resolver, err := selector.Select(ctx)
		if err != nil {
			t.Fatalf("Select failed: %v", err)
		}
		selected[resolver.Address()]++
	}

	// Each resolver should be selected twice
	for addr, count := range selected {
		if count != 2 {
			t.Errorf("Resolver %s selected %d times, want 2", addr, count)
		}
	}
}

// TestRoundRobinSelectorEmpty tests round-robin with no resolvers
func TestRoundRobinSelectorEmpty(t *testing.T) {
	selector := NewRoundRobinSelector(nil)

	_, err := selector.Select(context.Background())
	if err == nil {
		t.Error("Select should fail with no resolvers")
	}
	if err != ErrNoResolvers {
		t.Errorf("Error = %v, want ErrNoResolvers", err)
	}
}

// TestFailoverSelector tests failover selection
func TestFailoverSelector(t *testing.T) {
	resolvers := []upstream.Resolver{
		&mockResolver{protocol: "udp", address: "8.8.8.8:53"},
		&mockResolver{protocol: "udp", address: "8.8.4.4:53"},
		&mockResolver{protocol: "udp", address: "1.1.1.1:53"},
	}
	priorities := []int{1, 2, 3} // First resolver has highest priority

	cfg := &config.HealthCheckConfig{
		Enabled:           false, // Disable health check for test
		FailureThreshold:  3,
		RecoveryThreshold: 2,
	}

	selector := NewFailoverSelector(resolvers, priorities, cfg)
	defer selector.Stop()

	// Test name
	if selector.Name() != "failover" {
		t.Errorf("Name = %s, want failover", selector.Name())
	}

	// Should always select highest priority (first) resolver
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		resolver, err := selector.Select(ctx)
		if err != nil {
			t.Fatalf("Select failed: %v", err)
		}
		if resolver.Address() != "8.8.8.8:53" {
			t.Errorf("Selected resolver = %s, want 8.8.8.8:53", resolver.Address())
		}
	}
}

// TestFailoverSelectorFailover tests failover when primary fails
func TestFailoverSelectorFailover(t *testing.T) {
	resolvers := []upstream.Resolver{
		&mockResolver{protocol: "udp", address: "primary:53"},
		&mockResolver{protocol: "udp", address: "backup:53"},
	}
	priorities := []int{1, 2}

	cfg := &config.HealthCheckConfig{
		Enabled:           false,
		FailureThreshold:  2,
		RecoveryThreshold: 1,
	}

	selector := NewFailoverSelector(resolvers, priorities, cfg)
	defer selector.Stop()

	// Report failures for primary
	selector.ReportFailure(resolvers[0])
	selector.ReportFailure(resolvers[0])

	// Check primary is marked as unhealthy
	healthy, _ := selector.GetStatus(0)
	if healthy {
		t.Error("Primary should be marked as unhealthy")
	}

	// Should now select backup
	resolver, err := selector.Select(context.Background())
	if err != nil {
		t.Fatalf("Select failed: %v", err)
	}
	if resolver.Address() != "backup:53" {
		t.Errorf("Selected resolver = %s, want backup:53", resolver.Address())
	}
}

// TestFailoverSelectorRecovery tests resolver recovery
func TestFailoverSelectorRecovery(t *testing.T) {
	resolvers := []upstream.Resolver{
		&mockResolver{protocol: "udp", address: "primary:53"},
		&mockResolver{protocol: "udp", address: "backup:53"},
	}
	priorities := []int{1, 2}

	cfg := &config.HealthCheckConfig{
		Enabled:           false,
		FailureThreshold:  1,
		RecoveryThreshold: 2,
	}

	selector := NewFailoverSelector(resolvers, priorities, cfg)
	defer selector.Stop()

	// Mark primary as failed
	selector.ReportFailure(resolvers[0])

	healthy, _ := selector.GetStatus(0)
	if healthy {
		t.Error("Primary should be unhealthy")
	}

	// Report success twice to recover
	selector.ReportSuccess(resolvers[0])
	selector.ReportSuccess(resolvers[0])

	healthy, _ = selector.GetStatus(0)
	if !healthy {
		t.Error("Primary should be recovered")
	}
}

// TestFailoverSelectorEmpty tests failover with no resolvers
func TestFailoverSelectorEmpty(t *testing.T) {
	cfg := &config.HealthCheckConfig{Enabled: false}
	selector := NewFailoverSelector(nil, nil, cfg)
	defer selector.Stop()

	_, err := selector.Select(context.Background())
	if err != ErrNoResolvers {
		t.Errorf("Error = %v, want ErrNoResolvers", err)
	}
}

// TestFastestSelector tests fastest response selection
func TestFastestSelector(t *testing.T) {
	resolvers := []upstream.Resolver{
		&mockResolver{protocol: "udp", address: "slow:53", latency: 50 * time.Millisecond},
		&mockResolver{protocol: "udp", address: "fast:53", latency: 5 * time.Millisecond},
		&mockResolver{protocol: "udp", address: "medium:53", latency: 20 * time.Millisecond},
	}

	cfg := &config.FastestConfig{
		WindowSize: 100,
		MinSamples: 3,
		Cooldown:   0, // No cooldown for test
	}

	selector := NewFastestSelector(resolvers, cfg)

	// Test name
	if selector.Name() != "fastest" {
		t.Errorf("Name = %s, want fastest", selector.Name())
	}

	// Report latencies to build statistics
	// Slow resolver
	selector.ReportSuccessWithLatency(resolvers[0], 50*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[0], 55*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[0], 45*time.Millisecond)

	// Fast resolver
	selector.ReportSuccessWithLatency(resolvers[1], 5*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[1], 6*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[1], 4*time.Millisecond)

	// Medium resolver
	selector.ReportSuccessWithLatency(resolvers[2], 20*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[2], 22*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[2], 18*time.Millisecond)

	// Now should always select the fastest resolver
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		resolver, err := selector.Select(ctx)
		if err != nil {
			t.Fatalf("Select failed: %v", err)
		}
		if resolver.Address() != "fast:53" {
			t.Errorf("Selected resolver = %s, want fast:53", resolver.Address())
		}
	}
}

// TestFastestSelectorWithFailure tests fastest selection with failure penalty
func TestFastestSelectorWithFailure(t *testing.T) {
	resolvers := []upstream.Resolver{
		&mockResolver{protocol: "udp", address: "resolver1:53"},
		&mockResolver{protocol: "udp", address: "resolver2:53"},
	}

	cfg := &config.FastestConfig{
		WindowSize: 100,
		MinSamples: 3, // Need 3 samples to consider stats valid
		Cooldown:   0,
	}

	selector := NewFastestSelector(resolvers, cfg)

	// Make resolver1 appear fast initially (need 3 samples for min_samples)
	selector.ReportSuccessWithLatency(resolvers[0], 5*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[0], 5*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[0], 5*time.Millisecond)

	// Make resolver2 appear slower (need 3 samples)
	selector.ReportSuccessWithLatency(resolvers[1], 50*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[1], 50*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[1], 50*time.Millisecond)

	// Should select resolver1 (faster)
	resolver, err := selector.Select(context.Background())
	if err != nil {
		t.Fatalf("Select failed: %v", err)
	}
	if resolver.Address() != "resolver1:53" {
		t.Errorf("Expected resolver1 to be selected first")
	}

	// Report failure for resolver1 (adds penalty to samples)
	selector.ReportFailure(resolvers[0])

	// Report success to trigger avg recalculation with the penalty
	selector.ReportSuccessWithLatency(resolvers[0], 5*time.Millisecond)

	// After failure penalty, resolver1 should have much higher avg
	stats := selector.GetStats()
	if stats[0].AvgLatency <= stats[1].AvgLatency {
		t.Errorf("Resolver1 should have higher avg latency than resolver2 after failure penalty: %v vs %v", stats[0].AvgLatency, stats[1].AvgLatency)
	}
}

// TestFastestSelectorEmpty tests fastest with no resolvers
func TestFastestSelectorEmpty(t *testing.T) {
	cfg := &config.FastestConfig{}
	selector := NewFastestSelector(nil, cfg)

	_, err := selector.Select(context.Background())
	if err != ErrNoResolvers {
		t.Errorf("Error = %v, want ErrNoResolvers", err)
	}
}

// TestNoResolversError tests error message
func TestNoResolversError(t *testing.T) {
	err := ErrNoResolvers
	if err.Error() != "no resolvers available" {
		t.Errorf("Error message = %s, want 'no resolvers available'", err.Error())
	}
}

// TestBaseSelector tests base selector methods
func TestBaseSelector(t *testing.T) {
	resolvers := []upstream.Resolver{
		&mockResolver{protocol: "udp", address: "8.8.8.8:53"},
		&mockResolver{protocol: "doh", address: "https://dns.google/dns-query"},
	}

	base := &BaseSelector{
		name:      "test",
		resolvers: resolvers,
	}

	// Test Name
	if base.Name() != "test" {
		t.Errorf("Name = %s, want test", base.Name())
	}

	// Test Resolvers
	if len(base.Resolvers()) != 2 {
		t.Errorf("Resolvers count = %d, want 2", len(base.Resolvers()))
	}

	// Test ResolverInfo
	infos := base.ResolverInfo()
	if len(infos) != 2 {
		t.Errorf("ResolverInfo count = %d, want 2", len(infos))
	}
	if infos[0].Protocol != "udp" {
		t.Errorf("First resolver protocol = %s, want udp", infos[0].Protocol)
	}
}

// TestFailoverSelectorAllUnhealthy tests when all resolvers are unhealthy
func TestFailoverSelectorAllUnhealthy(t *testing.T) {
	resolvers := []upstream.Resolver{
		&mockResolver{protocol: "udp", address: "resolver1:53"},
		&mockResolver{protocol: "udp", address: "resolver2:53"},
	}
	priorities := []int{1, 2}

	cfg := &config.HealthCheckConfig{
		Enabled:           false,
		FailureThreshold:  1,
		RecoveryThreshold: 1,
	}

	selector := NewFailoverSelector(resolvers, priorities, cfg)
	defer selector.Stop()

	// Mark all as failed
	selector.ReportFailure(resolvers[0])
	selector.ReportFailure(resolvers[1])

	// Should still return a resolver (highest priority one)
	resolver, err := selector.Select(context.Background())
	if err != nil {
		t.Fatalf("Select should not fail: %v", err)
	}
	if resolver.Address() != "resolver1:53" {
		t.Errorf("Should return highest priority resolver when all unhealthy")
	}
}

// TestResolverStats tests resolver statistics
func TestResolverStats(t *testing.T) {
	resolvers := []upstream.Resolver{
		&mockResolver{protocol: "udp", address: "resolver:53"},
	}

	cfg := &config.FastestConfig{
		WindowSize: 10,
		MinSamples: 1,
		Cooldown:   0,
	}

	selector := NewFastestSelector(resolvers, cfg)

	// Report some latencies
	selector.ReportSuccessWithLatency(resolvers[0], 10*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[0], 20*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[0], 30*time.Millisecond)

	stats := selector.GetStats()
	if len(stats) != 1 {
		t.Fatalf("Expected 1 stats entry, got %d", len(stats))
	}

	if stats[0].Samples != 3 {
		t.Errorf("Samples = %d, want 3", stats[0].Samples)
	}

	expectedAvg := (10 + 20 + 30) / 3 * time.Millisecond
	if stats[0].AvgLatency != expectedAvg {
		t.Errorf("AvgLatency = %v, want %v", stats[0].AvgLatency, expectedAvg)
	}
}

// TestFastestSelectorSlidingWindow tests sliding window behavior
func TestFastestSelectorSlidingWindow(t *testing.T) {
	resolvers := []upstream.Resolver{
		&mockResolver{protocol: "udp", address: "resolver:53"},
	}

	cfg := &config.FastestConfig{
		WindowSize: 3,
		MinSamples: 1,
		Cooldown:   0,
	}

	selector := NewFastestSelector(resolvers, cfg)

	// Add 5 samples (window size is 3)
	selector.ReportSuccessWithLatency(resolvers[0], 100*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[0], 100*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[0], 100*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[0], 10*time.Millisecond)
	selector.ReportSuccessWithLatency(resolvers[0], 10*time.Millisecond)

	stats := selector.GetStats()
	if stats[0].Samples != 3 {
		t.Errorf("Samples = %d, want 3 (window size)", stats[0].Samples)
	}

	// Avg should be based on last 3 samples: 100, 10, 10 -> avg ~40ms
	// But due to window sliding, it should be: 10, 10, and one more
	expectedAvg := (100 + 10 + 10) / 3 * time.Millisecond
	if stats[0].AvgLatency != expectedAvg {
		t.Errorf("AvgLatency = %v, want %v", stats[0].AvgLatency, expectedAvg)
	}
}

// TestContextCancellation tests context cancellation
func TestContextCancellation(t *testing.T) {
	resolvers := []upstream.Resolver{
		&mockResolver{protocol: "udp", address: "resolver:53"},
	}

	selector := NewRoundRobinSelector(resolvers)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Selector should still work (doesn't block)
	resolver, err := selector.Select(ctx)
	if err != nil {
		t.Logf("Select with canceled context returned error: %v", err)
	}
	if resolver != nil {
		t.Log("Select returned a resolver despite canceled context")
	}
}

// TestFailoverWithErrors tests failover behavior with errors
func TestFailoverWithErrors(t *testing.T) {
	resolvers := []upstream.Resolver{
		&mockResolver{protocol: "udp", address: "resolver1:53", err: errors.New("timeout")},
		&mockResolver{protocol: "udp", address: "resolver2:53"},
	}
	priorities := []int{1, 2}

	cfg := &config.HealthCheckConfig{
		Enabled:           false,
		FailureThreshold:  1,
		RecoveryThreshold: 1,
	}

	selector := NewFailoverSelector(resolvers, priorities, cfg)
	defer selector.Stop()

	// Simulate failure for resolver1
	_, err := resolvers[0].Resolve(context.Background(), nil)
	if err == nil {
		t.Error("Expected mock resolver to return error")
	}

	// Report the failure
	selector.ReportFailure(resolvers[0])

	// Resolver1 should now be marked as unhealthy
	healthy, _ := selector.GetStatus(0)
	if healthy {
		t.Error("Resolver1 should be unhealthy after failure")
	}
}
