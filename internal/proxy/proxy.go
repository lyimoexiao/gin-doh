// Package proxy provides HTTP and SOCKS5 proxy support for upstream connections.
package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/lyimoexiao/gin-doh/internal/config"
)

// Dialer is the proxy dialer interface
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Manager manages proxy connections
type Manager struct {
	config *config.ProxyConfig
	dialer Dialer
}

// NewManager creates a new proxy manager
func NewManager(cfg *config.ProxyConfig) (*Manager, error) {
	if cfg == nil || !cfg.Enabled {
		return &Manager{dialer: &net.Dialer{}}, nil
	}

	var dialer Dialer

	switch cfg.Type {
	case "http":
		d, err := newHTTPProxyDialer(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP proxy dialer: %w", err)
		}
		dialer = d
	case "socks5":
		d, err := newSocks5ProxyDialer(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 proxy dialer: %w", err)
		}
		dialer = d
	default:
		return nil, fmt.Errorf("unsupported proxy type: %s", cfg.Type)
	}

	return &Manager{
		config: cfg,
		dialer: dialer,
	}, nil
}

// DialContext dials through the proxy
func (m *Manager) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return m.dialer.DialContext(ctx, network, addr)
}

// Enabled checks if proxy is enabled
func (m *Manager) Enabled() bool {
	return m.config != nil && m.config.Enabled
}

// httpProxyDialer is an HTTP proxy dialer
type httpProxyDialer struct {
	proxyURL  *url.URL
	tlsConfig *tls.Config
	base      *net.Dialer
}

func newHTTPProxyDialer(cfg *config.ProxyConfig) (*httpProxyDialer, error) {
	u, err := url.Parse(fmt.Sprintf("http://%s", cfg.Address))
	if err != nil {
		return nil, err
	}

	if cfg.Username != "" && cfg.Password != "" {
		u.User = url.UserPassword(cfg.Username, cfg.Password)
	}

	return &httpProxyDialer{
		proxyURL: u,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		base: &net.Dialer{},
	}, nil
}

func (d *httpProxyDialer) DialContext(ctx context.Context, _, addr string) (net.Conn, error) {
	// Connect to proxy server
	conn, err := d.base.DialContext(ctx, "tcp", d.proxyURL.Host)
	if err != nil {
		return nil, err
	}

	// Send CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)

	if d.proxyURL.User != nil {
		password, _ := d.proxyURL.User.Password()
		auth := basicAuth(d.proxyURL.User.Username(), password)
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}

	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Check response status
	resp := string(buf[:n])
	if len(resp) < 12 || resp[9:12] != "200" {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy connect failed: %s", resp)
	}

	return conn, nil
}

// basicAuth generates a Basic authentication string
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// socks5ProxyDialer is a SOCKS5 proxy dialer
type socks5ProxyDialer struct {
	address  string
	username string
	password string
	base     *net.Dialer
}

func newSocks5ProxyDialer(cfg *config.ProxyConfig) (*socks5ProxyDialer, error) {
	return &socks5ProxyDialer{
		address:  cfg.Address,
		username: cfg.Username,
		password: cfg.Password,
		base:     &net.Dialer{},
	}, nil
}

func (d *socks5ProxyDialer) DialContext(ctx context.Context, _, addr string) (net.Conn, error) {
	// Connect to SOCKS5 proxy server
	conn, err := d.base.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}

	// SOCKS5 handshake
	if err := d.handshake(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Send connect request
	if err := d.connect(conn, addr); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func (d *socks5ProxyDialer) handshake(conn net.Conn) error {
	// Version 5, auth method count
	var authMethods []byte
	if d.username != "" && d.password != "" {
		authMethods = []byte{0x05, 0x02, 0x00, 0x02} // No auth + username/password
	} else {
		authMethods = []byte{0x05, 0x01, 0x00} // No auth
	}

	if _, err := conn.Write(authMethods); err != nil {
		return err
	}

	// Read server response
	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		return err
	}

	if resp[0] != 0x05 {
		return fmt.Errorf("invalid SOCKS version: %d", resp[0])
	}

	// Handle authentication
	switch resp[1] {
	case 0x00: // No authentication required
		return nil
	case 0x02: // Username/password authentication
		return d.authenticate(conn)
	default:
		return fmt.Errorf("unsupported auth method: %d", resp[1])
	}
}

func (d *socks5ProxyDialer) authenticate(conn net.Conn) error {
	// Username/password authentication sub-negotiation
	auth := make([]byte, 0, 3+len(d.username)+len(d.password))
	auth = append(auth, 0x01, byte(len(d.username))) // Version + username length
	auth = append(auth, []byte(d.username)...)
	auth = append(auth, byte(len(d.password)))
	auth = append(auth, []byte(d.password)...)

	if _, err := conn.Write(auth); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		return err
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("authentication failed")
	}

	return nil
}

func (d *socks5ProxyDialer) connect(conn net.Conn, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	// Build connect request
	req := []byte{0x05, 0x01, 0x00} // Version 5, connect command, reserved

	// Address type
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			req = append(req, 0x01) // IPv4
			req = append(req, ip.To4()...)
		} else {
			req = append(req, 0x04) // IPv6
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("hostname too long")
		}
		req = append(req, 0x03, byte(len(host))) // Domain name
		req = append(req, []byte(host)...)
	}

	// Port
	req = append(req, byte(port>>8), byte(port&0xFF))

	if _, err := conn.Write(req); err != nil {
		return err
	}

	// Read response
	resp := make([]byte, 10)
	n, err := conn.Read(resp)
	if err != nil {
		return err
	}

	if n < 2 {
		return fmt.Errorf("invalid response")
	}

	if resp[0] != 0x05 {
		return fmt.Errorf("invalid SOCKS version: %d", resp[0])
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("connect failed: %d", resp[1])
	}

	return nil
}
