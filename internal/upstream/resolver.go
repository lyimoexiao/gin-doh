package upstream

import (
	"context"
	"net"
	"time"
)

// Resolver is the DNS resolver interface
type Resolver interface {
	// Resolve performs DNS resolution
	Resolve(ctx context.Context, query []byte) ([]byte, error)

	// Protocol returns the protocol type
	Protocol() string

	// Address returns the server address
	Address() string

	// String returns the server description
	String() string
}

// BaseResolver is the base resolver
type BaseResolver struct {
	protocol string
	address  string
	timeout  time.Duration
}

// Protocol returns the protocol type
func (r *BaseResolver) Protocol() string {
	return r.protocol
}

// Address returns the server address
func (r *BaseResolver) Address() string {
	return r.address
}

// String returns the server description
func (r *BaseResolver) String() string {
	return r.protocol + "://" + r.address
}

// ResolverInfo contains resolver information
type ResolverInfo struct {
	Protocol string
	Address  string
}

// ResolverStats contains resolver statistics
type ResolverStats struct {
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	TotalLatency    time.Duration
	AvgLatency      time.Duration
}

// UDPResolver is a UDP DNS resolver
type UDPResolver struct {
	BaseResolver
}

// NewUDPResolver creates a new UDP resolver
func NewUDPResolver(address string, timeout time.Duration) *UDPResolver {
	return &UDPResolver{
		BaseResolver: BaseResolver{
			protocol: "udp",
			address:  address,
			timeout:  timeout,
		},
	}
}

// Resolve performs DNS resolution
func (r *UDPResolver) Resolve(ctx context.Context, query []byte) ([]byte, error) {
	// Resolve server address
	addr, err := net.ResolveUDPAddr("udp", r.address)
	if err != nil {
		return nil, err
	}

	// Create local UDP connection
	localAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", localAddr, addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set timeout
	deadline := time.Now().Add(r.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	// Send query
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	// Read response
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

// TCPResolver is a TCP DNS resolver
type TCPResolver struct {
	BaseResolver
}

// NewTCPResolver creates a new TCP resolver
func NewTCPResolver(address string, timeout time.Duration) *TCPResolver {
	return &TCPResolver{
		BaseResolver: BaseResolver{
			protocol: "tcp",
			address:  address,
			timeout:  timeout,
		},
	}
}

// Resolve performs DNS resolution
func (r *TCPResolver) Resolve(ctx context.Context, query []byte) ([]byte, error) {
	// Create TCP connection
	dialer := &net.Dialer{Timeout: r.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", r.address)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set timeout
	deadline := time.Now().Add(r.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	// TCP DNS messages need 2-byte length prefix
	msg := make([]byte, 2+len(query))
	msg[0] = byte(len(query) >> 8)
	msg[1] = byte(len(query))
	copy(msg[2:], query)

	// Send query
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}

	// Read length prefix
	lenBuf := make([]byte, 2)
	if _, err := conn.Read(lenBuf); err != nil {
		return nil, err
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	// Read response
	resp := make([]byte, respLen)
	if _, err := conn.Read(resp); err != nil {
		return nil, err
	}

	return resp, nil
}
