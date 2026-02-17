package ech

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
)

// ServerECHConfig manages server-side ECH configuration
type ServerECHConfig struct {
	Keys        []Key
	ConfigList  []byte // Config list to send to clients
	RetryConfig []byte // Retry config list
	PublicName  string
}

// NewServerECHConfig creates a new server-side ECH config
func NewServerECHConfig(publicName string) *ServerECHConfig {
	return &ServerECHConfig{
		PublicName: publicName,
	}
}

// AddKey adds an ECH key
func (s *ServerECHConfig) AddKey(key *Key) error {
	s.Keys = append(s.Keys, *key)
	return s.rebuildConfigList()
}

// GenerateAndAddKey generates and adds a new key
func (s *ServerECHConfig) GenerateAndAddKey(configID uint8) error {
	key, err := GenerateKey(configID, s.PublicName)
	if err != nil {
		return err
	}
	return s.AddKey(key)
}

// rebuildConfigList rebuilds the configuration list
func (s *ServerECHConfig) rebuildConfigList() error {
	var configs []Config
	for _, key := range s.Keys {
		cfg := key.GenerateConfig(s.PublicName)
		configs = append(configs, *cfg)
	}

	data, err := MarshalConfigList(configs)
	if err != nil {
		return err
	}

	s.ConfigList = data
	return nil
}

// LoadKeysFromFile loads keys from files
func (s *ServerECHConfig) LoadKeysFromFile(keyPaths map[uint8]string) error {
	for configID, path := range keyPaths {
		key, err := LoadPrivateKey(path, configID)
		if err != nil {
			return fmt.Errorf("failed to load key %d from %s: %w", configID, path, err)
		}
		s.Keys = append(s.Keys, *key)
	}
	return s.rebuildConfigList()
}

// LoadConfigListFromFile loads a configuration list from a file
func (s *ServerECHConfig) LoadConfigListFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Try to decode Base64
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		data = decoded
	}

	s.ConfigList = data
	return nil
}

// LoadRetryConfigFromFile loads a retry configuration from a file
func (s *ServerECHConfig) LoadRetryConfigFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Try to decode Base64
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		data = decoded
	}

	s.RetryConfig = data
	return nil
}

// GetTLSConfig returns ECH-related TLS configuration
// Note: Go standard library currently only supports client-side ECH, server-side ECH support is limited
func (s *ServerECHConfig) GetTLSConfig(baseConfig *tls.Config) (*tls.Config, error) {
	if baseConfig == nil {
		baseConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}

	// Go 1.25+ server-side ECH support requires EncryptedClientHelloKeys
	// Here we prepare the configuration, actual support depends on Go version

	// Set minimum version to TLS 1.3
	baseConfig.MinVersion = tls.VersionTLS13

	return baseConfig, nil
}

// ClientECHConfig represents client-side ECH configuration
type ClientECHConfig struct {
	ConfigList []byte
}

// NewClientECHConfig creates a new client-side ECH config
func NewClientECHConfig() *ClientECHConfig {
	return &ClientECHConfig{}
}

// LoadConfigListFromFile loads a configuration list from a file
func (c *ClientECHConfig) LoadConfigListFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Try to decode Base64
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		data = decoded
	}

	c.ConfigList = data
	return nil
}

// LoadConfigListFromBase64 loads a configuration list from Base64
func (c *ClientECHConfig) LoadConfigListFromBase64(encoded string) error {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	c.ConfigList = data
	return nil
}

// GetTLSConfig returns TLS client config with ECH configuration
func (c *ClientECHConfig) GetTLSConfig(baseConfig *tls.Config) (*tls.Config, error) {
	if baseConfig == nil {
		baseConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}

	if len(c.ConfigList) > 0 {
		// Go 1.23+ supports EncryptedClientHelloConfigList
		baseConfig.EncryptedClientHelloConfigList = c.ConfigList
	}

	return baseConfig, nil
}

// KeyProvider is the ECH key provider interface
type KeyProvider interface {
	// GetKey returns a key by configuration ID
	GetKey(configID uint8) (*Key, bool)
	// GetAllKeys returns all keys
	GetAllKeys() []Key
}

// GetKey returns a key by ID
func (s *ServerECHConfig) GetKey(configID uint8) (*Key, bool) {
	for i := range s.Keys {
		if s.Keys[i].ConfigID == configID {
			return &s.Keys[i], true
		}
	}
	return nil, false
}

// GetAllKeys returns all keys
func (s *ServerECHConfig) GetAllKeys() []Key {
	return s.Keys
}

// PEMBlock represents a PEM block structure
type PEMBlock struct {
	Type  string
	Bytes []byte
}

// encodePEM encodes a PEM block
func encodePEM(block *PEMBlock) []byte {
	return []byte(fmt.Sprintf("-----BEGIN %s-----\n%s-----END %s-----\n",
		block.Type,
		base64.StdEncoding.EncodeToString(block.Bytes),
		block.Type))
}

// GenerateKeyPair generates an ECH key pair and saves to files
func GenerateKeyPair(configID uint8, publicKeyFile, privateKeyFile string) error {
	key, err := GenerateKey(configID, "")
	if err != nil {
		return err
	}

	// Save private key
	if err := key.SavePrivateKey(privateKeyFile); err != nil {
		return err
	}

	// Save public key
	pubKeyBlock := &PEMBlock{
		Type:  "ECH PUBLIC KEY",
		Bytes: key.PublicKey.Bytes(),
	}
	pubKeyData := encodePEM(pubKeyBlock)
	return os.WriteFile(publicKeyFile, pubKeyData, 0o644)
}

// GreaseConfig represents ECH GREASE configuration (for sending fake ECH extensions)
type GreaseConfig struct {
	Enabled bool
}

// NewGreaseConfig creates a new GREASE config
func NewGreaseConfig() *GreaseConfig {
	return &GreaseConfig{
		Enabled: true,
	}
}

// GenerateGreaseECH generates GREASE ECH extension data
func (g *GreaseConfig) GenerateGreaseECH() []byte {
	// Generate random data to simulate ECH extension
	// Actual implementation should follow draft-ietf-tls-esni
	data := make([]byte, 128)
	_, _ = rand.Read(data)
	return data
}

// ParseClientHelloECH parses ECH info from ClientHello
func ParseClientHelloECH(hello []byte) (hasECH, isInner bool, configID uint8, err error) {
	// Simplified ECH extension parsing
	// Actual implementation requires full TLS extension parsing

	if len(hello) < 43 {
		return false, false, 0, nil
	}

	// Find ECH extension (extension type 0xfe0d)
	// This is just a placeholder, actual implementation needs full parsing

	return false, false, 0, nil
}

// DecryptClientHello decrypts ECH ClientHello (server-side use)
func DecryptClientHello(_ []byte, _ *Key) ([]byte, error) {
	// HPKE decryption implementation
	// This requires full HPKE implementation

	return nil, fmt.Errorf("ECH decryption not implemented")
}

// EncryptedClientHelloKey represents ECH key format for Go 1.25+
type EncryptedClientHelloKey struct {
	ID         uint8
	PrivateKey *ecdh.PrivateKey
}

// ToGoECHKey converts to Go standard library ECH key format
func (k *Key) ToGoECHKey() *EncryptedClientHelloKey {
	return &EncryptedClientHelloKey{
		ID:         k.ConfigID,
		PrivateKey: k.PrivateKey,
	}
}

// ParseEncryptedClientHelloConfigList parses ECH config list (simplified)
func ParseEncryptedClientHelloConfigList(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, ErrInvalidECHConfigList
	}

	listLen := binary.BigEndian.Uint16(data[0:2])
	if len(data) < int(listLen)+2 {
		return nil, ErrInvalidECHConfigList
	}

	return data, nil
}
