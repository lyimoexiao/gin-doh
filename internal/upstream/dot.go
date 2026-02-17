package upstream

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/lyimoexiao/gin-doh/internal/proxy"
)

// DoTResolver is a DNS-over-TLS resolver
type DoTResolver struct {
	BaseResolver
	serverName string
	proxyMgr   *proxy.Manager
}

// NewDoTResolver creates a new DoT resolver
func NewDoTResolver(address, serverName string, timeout time.Duration, proxyMgr *proxy.Manager) *DoTResolver {
	return &DoTResolver{
		BaseResolver: BaseResolver{
			protocol: "dot",
			address:  address,
			timeout:  timeout,
		},
		serverName: serverName,
		proxyMgr:   proxyMgr,
	}
}

// Resolve performs DNS resolution
func (r *DoTResolver) Resolve(ctx context.Context, query []byte) ([]byte, error) {
	var conn net.Conn
	var err error

	// Create connection
	dialer := &net.Dialer{Timeout: r.timeout}

	if r.proxyMgr != nil && r.proxyMgr.Enabled() {
		// Connect through proxy
		conn, err = r.proxyMgr.DialContext(ctx, "tcp", r.address)
		if err != nil {
			return nil, err
		}
	} else {
		// Direct connection
		conn, err = dialer.DialContext(ctx, "tcp", r.address)
		if err != nil {
			return nil, err
		}
	}
	defer func() { _ = conn.Close() }()

	// Set timeout
	deadline := time.Now().Add(r.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	// TLS handshake
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         r.serverName,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	})

	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	// TCP DNS messages need 2-byte length prefix
	msg := make([]byte, 2+len(query))
	msg[0] = byte(len(query) >> 8)
	msg[1] = byte(len(query))
	copy(msg[2:], query)

	// Send query
	if _, err := tlsConn.Write(msg); err != nil {
		return nil, err
	}

	// Read length prefix
	lenBuf := make([]byte, 2)
	if _, err := tlsConn.Read(lenBuf); err != nil {
		return nil, err
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	// Read response
	resp := make([]byte, respLen)
	if _, err := tlsConn.Read(resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// String returns server description
func (r *DoTResolver) String() string {
	return "dot://" + r.address + " (" + r.serverName + ")"
}
