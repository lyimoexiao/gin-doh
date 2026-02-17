package upstream

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/lyimoexiao/gin-doh/internal/proxy"
)

// DoTResolver DNS-over-TLS 解析器
type DoTResolver struct {
	BaseResolver
	serverName string
	proxyMgr   *proxy.Manager
}

// NewDoTResolver 创建 DoT 解析器
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

// Resolve 执行 DNS 解析
func (r *DoTResolver) Resolve(ctx context.Context, query []byte) ([]byte, error) {
	var conn net.Conn
	var err error

	// 创建连接
	dialer := &net.Dialer{Timeout: r.timeout}

	if r.proxyMgr != nil && r.proxyMgr.Enabled() {
		// 通过代理连接
		conn, err = r.proxyMgr.DialContext(ctx, "tcp", r.address)
		if err != nil {
			return nil, err
		}
	} else {
		// 直接连接
		conn, err = dialer.DialContext(ctx, "tcp", r.address)
		if err != nil {
			return nil, err
		}
	}
	defer conn.Close()

	// 设置超时
	deadline := time.Now().Add(r.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)

	// TLS 握手
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         r.serverName,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	})

	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	// TCP DNS 消息需要 2 字节长度前缀
	msg := make([]byte, 2+len(query))
	msg[0] = byte(len(query) >> 8)
	msg[1] = byte(len(query))
	copy(msg[2:], query)

	// 发送查询
	if _, err := tlsConn.Write(msg); err != nil {
		return nil, err
	}

	// 读取长度前缀
	lenBuf := make([]byte, 2)
	if _, err := tlsConn.Read(lenBuf); err != nil {
		return nil, err
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	// 读取响应
	resp := make([]byte, respLen)
	if _, err := tlsConn.Read(resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// String 返回服务器描述
func (r *DoTResolver) String() string {
	return "dot://" + r.address + " (" + r.serverName + ")"
}
