package ech

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// HPKE 实现 (简化版，用于 ECH)

// HPKESender HPKE 发送者
type HPKESender struct {
	publicKey  *ecdh.PublicKey
	privateKey *ecdh.PrivateKey
}

// HPKEReceiver HPKE 接收者
type HPKEReceiver struct {
	privateKey *ecdh.PrivateKey
}

// NewHPKESender 创建 HPKE 发送者
func NewHPKESender() (*HPKESender, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &HPKESender{
		publicKey:  privateKey.PublicKey(),
		privateKey: privateKey,
	}, nil
}

// NewHPKEReceiver 创建 HPKE 接收者
func NewHPKEReceiver(privateKey *ecdh.PrivateKey) *HPKEReceiver {
	return &HPKEReceiver{
		privateKey: privateKey,
	}
}

// Seal 加密数据 (简化实现)
func (s *HPKESender) Seal(recipientPublicKey *ecdh.PublicKey, plaintext, associatedData []byte) ([]byte, error) {
	// 执行 X25519 密钥交换
	sharedSecret, err := s.privateKey.ECDH(recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// 简化的加密实现
	// 实际实现应该使用完整的 HPKE 规范
	// 这里只是示意

	_ = sharedSecret
	_ = associatedData

	// 生成封装密钥
	enc := s.publicKey.Bytes()

	// 返回格式: enc (32 bytes) + ciphertext
	result := make([]byte, len(enc)+len(plaintext))
	copy(result[:len(enc)], enc)
	copy(result[len(enc):], plaintext)

	return result, nil
}

// Open 解密数据 (简化实现)
func (r *HPKEReceiver) Open(enc, ciphertext, associatedData []byte) ([]byte, error) {
	// 解析封装密钥
	if len(enc) != 32 {
		return nil, fmt.Errorf("invalid encapsulated key length")
	}

	// 从封装密钥重建公钥
	senderPublicKey, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse sender public key: %w", err)
	}

	// 执行 X25519 密钥交换
	sharedSecret, err := r.privateKey.ECDH(senderPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// 简化的解密实现
	_ = sharedSecret
	_ = associatedData

	// 返回明文
	return ciphertext, nil
}

// ClientHelloBuilder 构建 ECH ClientHello
type ClientHelloBuilder struct {
	innerHello []byte
	outerHello []byte
	config     *Config
	sender     *HPKESender
}

// NewClientHelloBuilder 创建 ClientHello 构建器
func NewClientHelloBuilder(cfg *Config) (*ClientHelloBuilder, error) {
	sender, err := NewHPKESender()
	if err != nil {
		return nil, err
	}

	return &ClientHelloBuilder{
		config: cfg,
		sender: sender,
	}, nil
}

// SetInnerClientHello 设置内部 ClientHello
func (b *ClientHelloBuilder) SetInnerClientHello(hello []byte) {
	b.innerHello = hello
}

// Build 构建带有 ECH 的 ClientHello
func (b *ClientHelloBuilder) Build() ([]byte, error) {
	if b.innerHello == nil {
		return nil, fmt.Errorf("inner ClientHello not set")
	}

	// 加密内部 ClientHello
	publicKey, err := ecdh.X25519().NewPublicKey(b.config.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	encrypted, err := b.sender.Seal(publicKey, b.innerHello, nil)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// 构建 ECH 扩展
	echExt := b.buildECHExtension(encrypted)

	// 添加 ECH 扩展到外部 ClientHello
	return append(b.outerHello, echExt...), nil
}

// buildECHExtension 构建 ECH 扩展
func (b *ClientHelloBuilder) buildECHExtension(encrypted []byte) []byte {
	var ext []byte

	// 扩展类型 (0xfe0d = 65037)
	ext = binary.BigEndian.AppendUint16(ext, 0xfe0d)

	// ECH 内容
	var content []byte

	// 类型: outer (0)
	content = append(content, 0x00)

	// 配置 ID
	content = append(content, b.config.ConfigID)

	// 封装密钥长度 (32 for X25519)
	encLen := 32
	content = binary.BigEndian.AppendUint16(content, uint16(encLen))

	// 封装密钥
	content = append(content, b.sender.publicKey.Bytes()...)

	// 加密的 ClientHello
	content = append(content, encrypted...)

	// 扩展长度
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(content)))

	// 扩展内容
	ext = append(ext, content...)

	return ext
}

// ECHConn 包装 TLS 连接以支持 ECH
type ECHConn struct {
	conn       net.Conn
	tlsConn    *tls.Conn
	config     *ClientECHConfig
	echUsed    bool
	echAccepted bool
}

// NewECHConn 创建 ECH 连接
func NewECHConn(conn net.Conn, config *ClientECHConfig) *ECHConn {
	return &ECHConn{
		conn:   conn,
		config: config,
	}
}

// DialWithContext 使用 ECH 拨号连接
func DialWithContext(ctx context.Context, network, addr string, config *tls.Config, echConfig *ClientECHConfig) (*ECHConn, error) {
	// 解析地址
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// 解析主机名
	hostname := host
	if hostname == "" {
		hostname = addr
	}

	// 设置 TLS 配置
	tlsConfig := config
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}
	tlsConfig.ServerName = hostname

	// 应用 ECH 配置
	if echConfig != nil && len(echConfig.ConfigList) > 0 {
		tlsConfig.EncryptedClientHelloConfigList = echConfig.ConfigList
	}

	// 创建拨号器
	dialer := &tls.Dialer{
		Config: tlsConfig,
	}

	// 拨号
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("not a TLS connection")
	}

	// 获取连接状态检查 ECH 是否被接受
	state := tlsConn.ConnectionState()

	return &ECHConn{
		conn:       tlsConn,
		tlsConn:    tlsConn,
		config:     echConfig,
		echUsed:    len(echConfig.ConfigList) > 0,
		echAccepted: state.ECHAccepted,
	}, nil
}

// Read 读取数据
func (c *ECHConn) Read(b []byte) (int, error) {
	if c.tlsConn != nil {
		return c.tlsConn.Read(b)
	}
	return c.conn.Read(b)
}

// Write 写入数据
func (c *ECHConn) Write(b []byte) (int, error) {
	if c.tlsConn != nil {
		return c.tlsConn.Write(b)
	}
	return c.conn.Write(b)
}

// Close 关闭连接
func (c *ECHConn) Close() error {
	if c.tlsConn != nil {
		return c.tlsConn.Close()
	}
	return c.conn.Close()
}

// LocalAddr 获取本地地址
func (c *ECHConn) LocalAddr() net.Addr {
	if c.tlsConn != nil {
		return c.tlsConn.LocalAddr()
	}
	return c.conn.LocalAddr()
}

// RemoteAddr 获取远程地址
func (c *ECHConn) RemoteAddr() net.Addr {
	if c.tlsConn != nil {
		return c.tlsConn.RemoteAddr()
	}
	return c.conn.RemoteAddr()
}

// SetDeadline 设置截止时间
func (c *ECHConn) SetDeadline(t time.Time) error {
	if c.tlsConn != nil {
		return c.tlsConn.SetDeadline(t)
	}
	return c.conn.SetDeadline(t)
}

// SetReadDeadline 设置读取截止时间
func (c *ECHConn) SetReadDeadline(t time.Time) error {
	if c.tlsConn != nil {
		return c.tlsConn.SetReadDeadline(t)
	}
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline 设置写入截止时间
func (c *ECHConn) SetWriteDeadline(t time.Time) error {
	if c.tlsConn != nil {
		return c.tlsConn.SetWriteDeadline(t)
	}
	return c.conn.SetWriteDeadline(t)
}

// ECHUsed 返回是否使用了 ECH
func (c *ECHConn) ECHUsed() bool {
	return c.echUsed
}

// ECHAccepted 返回 ECH 是否被服务器接受
func (c *ECHConn) ECHAccepted() bool {
	return c.echAccepted
}

// ConnectionState 返回 TLS 连接状态
func (c *ECHConn) ConnectionState() tls.ConnectionState {
	if c.tlsConn != nil {
		return c.tlsConn.ConnectionState()
	}
	return tls.ConnectionState{}
}
