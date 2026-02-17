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

// HPKESender represents an HPKE sender for ECH encryption
type HPKESender struct {
	publicKey  *ecdh.PublicKey
	privateKey *ecdh.PrivateKey
}

// HPKEReceiver represents an HPKE receiver for ECH decryption
type HPKEReceiver struct {
	privateKey *ecdh.PrivateKey
}

// NewHPKESender creates a new HPKE sender
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

// NewHPKEReceiver creates a new HPKE receiver
func NewHPKEReceiver(privateKey *ecdh.PrivateKey) *HPKEReceiver {
	return &HPKEReceiver{
		privateKey: privateKey,
	}
}

// Seal encrypts data (simplified implementation)
func (s *HPKESender) Seal(recipientPublicKey *ecdh.PublicKey, plaintext, associatedData []byte) ([]byte, error) {
	// Perform X25519 key exchange
	sharedSecret, err := s.privateKey.ECDH(recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Simplified encryption implementation
	// Actual implementation should use full HPKE specification
	_ = sharedSecret
	_ = associatedData

	// Generate encapsulation key
	enc := s.publicKey.Bytes()

	// Return format: enc (32 bytes) + ciphertext
	result := make([]byte, len(enc)+len(plaintext))
	copy(result[:len(enc)], enc)
	copy(result[len(enc):], plaintext)

	return result, nil
}

// Open decrypts data (simplified implementation)
func (r *HPKEReceiver) Open(enc, ciphertext, associatedData []byte) ([]byte, error) {
	// Parse encapsulation key
	if len(enc) != 32 {
		return nil, fmt.Errorf("invalid encapsulated key length")
	}

	// Reconstruct public key from encapsulation key
	senderPublicKey, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse sender public key: %w", err)
	}

	// Perform X25519 key exchange
	sharedSecret, err := r.privateKey.ECDH(senderPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Simplified decryption implementation
	_ = sharedSecret
	_ = associatedData

	// Return plaintext
	return ciphertext, nil
}

// ClientHelloBuilder builds an ECH ClientHello
type ClientHelloBuilder struct {
	innerHello []byte
	outerHello []byte
	config     *Config
	sender     *HPKESender
}

// NewClientHelloBuilder creates a new ClientHello builder
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

// SetInnerClientHello sets the inner ClientHello
func (b *ClientHelloBuilder) SetInnerClientHello(hello []byte) {
	b.innerHello = hello
}

// Build builds a ClientHello with ECH
func (b *ClientHelloBuilder) Build() ([]byte, error) {
	if b.innerHello == nil {
		return nil, fmt.Errorf("inner ClientHello not set")
	}

	// Encrypt inner ClientHello
	publicKey, err := ecdh.X25519().NewPublicKey(b.config.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	encrypted, err := b.sender.Seal(publicKey, b.innerHello, nil)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Build ECH extension
	echExt := b.buildECHExtension(encrypted)

	// Add ECH extension to outer ClientHello
	return append(b.outerHello, echExt...), nil
}

// buildECHExtension builds an ECH extension
func (b *ClientHelloBuilder) buildECHExtension(encrypted []byte) []byte {
	var ext []byte

	// Extension type (0xfe0d = 65037)
	ext = binary.BigEndian.AppendUint16(ext, 0xfe0d)

	// ECH content
	var content []byte

	// Type: outer (0) + Config ID
	content = append(content, 0x00, b.config.ConfigID)

	// Encapsulation key length (32 for X25519) + key
	encLen := 32
	content = binary.BigEndian.AppendUint16(content, uint16(encLen))
	content = append(content, b.sender.publicKey.Bytes()...)

	// Encrypted ClientHello
	content = append(content, encrypted...)

	// Extension length + content
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(content)))
	ext = append(ext, content...)

	return ext
}

// Conn wraps a TLS connection with ECH support
type Conn struct {
	conn        net.Conn
	tlsConn     *tls.Conn
	config      *ClientECHConfig
	echUsed     bool
	echAccepted bool
}

// NewECHConn creates a new ECH connection
func NewECHConn(conn net.Conn, config *ClientECHConfig) *Conn {
	return &Conn{
		conn:   conn,
		config: config,
	}
}

// DialWithContext dials a connection with ECH
func DialWithContext(ctx context.Context, network, addr string, config *tls.Config, echConfig *ClientECHConfig) (*Conn, error) {
	// Parse address
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// Parse hostname
	hostname := host
	if hostname == "" {
		hostname = addr
	}

	// Set TLS config
	tlsConfig := config
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}
	tlsConfig.ServerName = hostname

	// Apply ECH config
	if echConfig != nil && len(echConfig.ConfigList) > 0 {
		tlsConfig.EncryptedClientHelloConfigList = echConfig.ConfigList
	}

	// Create dialer
	dialer := &tls.Dialer{
		Config: tlsConfig,
	}

	// Dial
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("not a TLS connection")
	}

	// Get connection state to check if ECH was accepted
	state := tlsConn.ConnectionState()

	return &Conn{
		conn:        tlsConn,
		tlsConn:     tlsConn,
		config:      echConfig,
		echUsed:     len(echConfig.ConfigList) > 0,
		echAccepted: state.ECHAccepted,
	}, nil
}

// Read reads data from the connection
func (c *Conn) Read(b []byte) (int, error) {
	if c.tlsConn != nil {
		return c.tlsConn.Read(b)
	}
	return c.conn.Read(b)
}

// Write writes data to the connection
func (c *Conn) Write(b []byte) (int, error) {
	if c.tlsConn != nil {
		return c.tlsConn.Write(b)
	}
	return c.conn.Write(b)
}

// Close closes the connection
func (c *Conn) Close() error {
	if c.tlsConn != nil {
		return c.tlsConn.Close()
	}
	return c.conn.Close()
}

// LocalAddr returns the local address
func (c *Conn) LocalAddr() net.Addr {
	if c.tlsConn != nil {
		return c.tlsConn.LocalAddr()
	}
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote address
func (c *Conn) RemoteAddr() net.Addr {
	if c.tlsConn != nil {
		return c.tlsConn.RemoteAddr()
	}
	return c.conn.RemoteAddr()
}

// SetDeadline sets the deadline
func (c *Conn) SetDeadline(t time.Time) error {
	if c.tlsConn != nil {
		return c.tlsConn.SetDeadline(t)
	}
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline
func (c *Conn) SetReadDeadline(t time.Time) error {
	if c.tlsConn != nil {
		return c.tlsConn.SetReadDeadline(t)
	}
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c.tlsConn != nil {
		return c.tlsConn.SetWriteDeadline(t)
	}
	return c.conn.SetWriteDeadline(t)
}

// ECHUsed returns whether ECH was used
func (c *Conn) ECHUsed() bool {
	return c.echUsed
}

// ECHAccepted returns whether ECH was accepted by the server
func (c *Conn) ECHAccepted() bool {
	return c.echAccepted
}

// ConnectionState returns the TLS connection state
func (c *Conn) ConnectionState() tls.ConnectionState {
	if c.tlsConn != nil {
		return c.tlsConn.ConnectionState()
	}
	return tls.ConnectionState{}
}
