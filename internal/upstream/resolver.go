package upstream

import (
	"context"
	"net"
	"time"
)

// Resolver DNS 解析器接口
type Resolver interface {
	// Resolve 执行 DNS 解析
	Resolve(ctx context.Context, query []byte) ([]byte, error)

	// Protocol 返回协议类型
	Protocol() string

	// Address 返回服务器地址
	Address() string

	// String 返回服务器描述
	String() string
}

// BaseResolver 基础解析器
type BaseResolver struct {
	protocol string
	address  string
	timeout  time.Duration
}

// Protocol 返回协议类型
func (r *BaseResolver) Protocol() string {
	return r.protocol
}

// Address 返回服务器地址
func (r *BaseResolver) Address() string {
	return r.address
}

// String 返回服务器描述
func (r *BaseResolver) String() string {
	return r.protocol + "://" + r.address
}

// ResolverInfo 解析器信息
type ResolverInfo struct {
	Protocol string
	Address  string
}

// ResolverStats 解析器统计信息
type ResolverStats struct {
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	TotalLatency    time.Duration
	AvgLatency      time.Duration
}

// UDPResolver UDP DNS 解析器
type UDPResolver struct {
	BaseResolver
	conn *net.UDPConn
}

// NewUDPResolver 创建 UDP 解析器
func NewUDPResolver(address string, timeout time.Duration) *UDPResolver {
	return &UDPResolver{
		BaseResolver: BaseResolver{
			protocol: "udp",
			address:  address,
			timeout:  timeout,
		},
	}
}

// Resolve 执行 DNS 解析
func (r *UDPResolver) Resolve(ctx context.Context, query []byte) ([]byte, error) {
	// 解析服务器地址
	addr, err := net.ResolveUDPAddr("udp", r.address)
	if err != nil {
		return nil, err
	}

	// 创建本地 UDP 连接
	localAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", localAddr, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 设置超时
	deadline := time.Now().Add(r.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)

	// 发送查询
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	// 读取响应
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

// TCPResolver TCP DNS 解析器
type TCPResolver struct {
	BaseResolver
}

// NewTCPResolver 创建 TCP 解析器
func NewTCPResolver(address string, timeout time.Duration) *TCPResolver {
	return &TCPResolver{
		BaseResolver: BaseResolver{
			protocol: "tcp",
			address:  address,
			timeout:  timeout,
		},
	}
}

// Resolve 执行 DNS 解析
func (r *TCPResolver) Resolve(ctx context.Context, query []byte) ([]byte, error) {
	// 创建 TCP 连接
	dialer := &net.Dialer{Timeout: r.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", r.address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 设置超时
	deadline := time.Now().Add(r.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)

	// TCP DNS 消息需要 2 字节长度前缀
	msg := make([]byte, 2+len(query))
	msg[0] = byte(len(query) >> 8)
	msg[1] = byte(len(query))
	copy(msg[2:], query)

	// 发送查询
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}

	// 读取长度前缀
	lenBuf := make([]byte, 2)
	if _, err := conn.Read(lenBuf); err != nil {
		return nil, err
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	// 读取响应
	resp := make([]byte, respLen)
	if _, err := conn.Read(resp); err != nil {
		return nil, err
	}

	return resp, nil
}
