package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"

	"github.com/lyimoexiao/gin-doh/internal/config"
)

// Dialer 代理拨号器接口
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Manager 代理管理器
type Manager struct {
	config *config.ProxyConfig
	dialer Dialer
}

// NewManager 创建代理管理器
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

// DialContext 通过代理拨号
func (m *Manager) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return m.dialer.DialContext(ctx, network, addr)
}

// Enabled 检查代理是否启用
func (m *Manager) Enabled() bool {
	return m.config != nil && m.config.Enabled
}

// HTTP 代理拨号器
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

func (d *httpProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// 连接到代理服务器
	conn, err := d.base.DialContext(ctx, "tcp", d.proxyURL.Host)
	if err != nil {
		return nil, err
	}

	// 发送 CONNECT 请求
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)

	if d.proxyURL.User != nil {
		password, _ := d.proxyURL.User.Password()
		auth := basicAuth(d.proxyURL.User.Username(), password)
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}

	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, err
	}

	// 读取响应
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// 检查响应状态
	resp := string(buf[:n])
	if len(resp) < 12 || resp[9:12] != "200" {
		conn.Close()
		return nil, fmt.Errorf("proxy connect failed: %s", resp)
	}

	return conn, nil
}

// basicAuth 生成 Basic 认证字符串
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// SOCKS5 代理拨号器
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

func (d *socks5ProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// 连接到 SOCKS5 代理服务器
	conn, err := d.base.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}

	// SOCKS5 握手
	if err := d.handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}

	// 发送连接请求
	if err := d.connect(conn, addr); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func (d *socks5ProxyDialer) handshake(conn net.Conn) error {
	// 版本 5，认证方法数量
	var authMethods []byte
	if d.username != "" && d.password != "" {
		authMethods = []byte{0x05, 0x02, 0x00, 0x02} // 无认证 + 用户名密码
	} else {
		authMethods = []byte{0x05, 0x01, 0x00} // 无认证
	}

	if _, err := conn.Write(authMethods); err != nil {
		return err
	}

	// 读取服务器响应
	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		return err
	}

	if resp[0] != 0x05 {
		return fmt.Errorf("invalid SOCKS version: %d", resp[0])
	}

	// 处理认证
	switch resp[1] {
	case 0x00: // 无需认证
		return nil
	case 0x02: // 用户名密码认证
		return d.authenticate(conn)
	default:
		return fmt.Errorf("unsupported auth method: %d", resp[1])
	}
}

func (d *socks5ProxyDialer) authenticate(conn net.Conn) error {
	// 用户名密码认证子协商
	auth := make([]byte, 0, 3+len(d.username)+len(d.password))
	auth = append(auth, 0x01) // 版本
	auth = append(auth, byte(len(d.username)))
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

	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	// 构建连接请求
	req := []byte{0x05, 0x01, 0x00} // 版本 5，连接命令，保留

	// 地址类型
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
		req = append(req, 0x03) // 域名
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	}

	// 端口
	req = append(req, byte(port>>8), byte(port&0xFF))

	if _, err := conn.Write(req); err != nil {
		return err
	}

	// 读取响应
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
