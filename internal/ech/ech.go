// Package ech provides ECH (Encrypted Client Hello) configuration management
// for both server-side and client-side ECH support.
package ech

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// ECH related constants
const (
	// ECHConfigVersion is the ECH configuration version
	ECHConfigVersion = 0xfe0d

	// HPKE KEM identifiers
	HPKEDHKEMX25519 uint16 = 0x0020

	// HPKE KDF identifiers
	HPKEHKDFSHA256 uint16 = 0x0001

	// HPKE AEAD identifiers
	HPKEAES128GCM        uint16 = 0x0001
	HPKEAES256GCM        uint16 = 0x0002
	HPKEChaCha20Poly1305 uint16 = 0x0003
)

// Config represents an ECH configuration (for server and client)
type Config struct {
	Version           uint8
	ConfigID          uint8
	KEMID             uint16
	PublicKey         []byte
	KDFID             uint16
	AEADID            uint16
	PublicName        string
	MaximumNameLength uint8
}

// ConfigList represents an ECH configuration list
type ConfigList struct {
	Configs []Config
}

// Key represents an ECH key pair
type Key struct {
	ConfigID   uint8
	PublicKey  *ecdh.PublicKey
	PrivateKey *ecdh.PrivateKey
}

var (
	// ErrInvalidECHConfig indicates an invalid ECH configuration
	ErrInvalidECHConfig = errors.New("invalid ECH config")
	// ErrInvalidECHConfigList indicates an invalid ECH configuration list
	ErrInvalidECHConfigList = errors.New("invalid ECH config list")
	// ErrUnsupportedKEM indicates an unsupported KEM algorithm
	ErrUnsupportedKEM = errors.New("unsupported KEM algorithm")
	// ErrInvalidKeyFormat indicates an invalid key format
	ErrInvalidKeyFormat = errors.New("invalid key format")
)

// ParseConfigList parses an ECH configuration list
func ParseConfigList(data []byte) (*ConfigList, error) {
	if len(data) < 2 {
		return nil, ErrInvalidECHConfigList
	}

	// Read config list length
	listLen := binary.BigEndian.Uint16(data[0:2])
	if len(data) < int(listLen)+2 {
		return nil, ErrInvalidECHConfigList
	}

	list := &ConfigList{}
	offset := 2
	remaining := int(listLen)

	for remaining > 0 {
		if remaining < 4 {
			return nil, ErrInvalidECHConfigList
		}

		// Read config length
		configLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if configLen+4 > remaining {
			return nil, ErrInvalidECHConfigList
		}

		config, err := parseConfig(data[offset : offset+4+configLen])
		if err != nil {
			return nil, err
		}

		list.Configs = append(list.Configs, *config)
		offset += 4 + configLen
		remaining -= 4 + configLen
	}

	return list, nil
}

// parseConfig parses a single ECH configuration
func parseConfig(data []byte) (*Config, error) {
	if len(data) < 10 {
		return nil, ErrInvalidECHConfig
	}

	offset := 0

	// Read config type length (2 bytes)
	configTypeLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Read config length (2 bytes)
	configLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	_ = configTypeLen // Ignore config type length

	if offset+configLen > len(data) {
		return nil, ErrInvalidECHConfig
	}

	configData := data[offset : offset+configLen]
	cfg, err := parseConfigInner(configData)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// parseConfigInner parses the inner structure of an ECH configuration
func parseConfigInner(data []byte) (*Config, error) {
	if len(data) < 8 {
		return nil, ErrInvalidECHConfig
	}

	offset := 0
	cfg := &Config{}

	// Version (2 bytes)
	cfg.Version = data[offset]
	offset += 2 // Skip version (uint16)

	// Config ID (1 byte)
	cfg.ConfigID = data[offset]
	offset++

	// KEM ID (2 bytes)
	cfg.KEMID = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Public key length (2 bytes)
	pubKeyLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+pubKeyLen > len(data) {
		return nil, ErrInvalidECHConfig
	}

	// Public key
	cfg.PublicKey = make([]byte, pubKeyLen)
	copy(cfg.PublicKey, data[offset:offset+pubKeyLen])
	offset += pubKeyLen

	// HPKE suite length (2 bytes)
	suiteLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Read first HPKE suite (KDF ID + AEAD ID)
	if offset+4 <= len(data) && suiteLen >= 4 {
		cfg.KDFID = binary.BigEndian.Uint16(data[offset : offset+2])
		cfg.AEADID = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += suiteLen
	}

	// Public name length (1 byte)
	if offset >= len(data) {
		return nil, ErrInvalidECHConfig
	}
	pubNameLen := int(data[offset])
	offset++

	// Public name
	if offset+pubNameLen > len(data) {
		return nil, ErrInvalidECHConfig
	}
	cfg.PublicName = string(data[offset : offset+pubNameLen])
	offset += pubNameLen

	// Maximum name length (1 byte)
	if offset >= len(data) {
		return nil, ErrInvalidECHConfig
	}
	cfg.MaximumNameLength = data[offset]

	return cfg, nil
}

// MarshalConfigList serializes an ECH configuration list
func MarshalConfigList(configs []Config) ([]byte, error) {
	var data []byte

	for _, cfg := range configs {
		configData, err := cfg.marshal()
		if err != nil {
			return nil, err
		}
		data = append(data, configData...)
	}

	// Add total length prefix
	result := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(result[0:2], uint16(len(data)))
	copy(result[2:], data)

	return result, nil
}

// marshal serializes a single ECH configuration
func (c *Config) marshal() ([]byte, error) {
	var inner []byte

	// Version
	inner = append(inner, 0x00, c.Version, c.ConfigID)

	// KEM ID
	inner = binary.BigEndian.AppendUint16(inner, c.KEMID)

	// Public key length and public key
	inner = binary.BigEndian.AppendUint16(inner, uint16(len(c.PublicKey)))
	inner = append(inner, c.PublicKey...)

	// HPKE suite (KDF ID + AEAD ID)
	inner = binary.BigEndian.AppendUint16(inner, 4) // One suite
	inner = binary.BigEndian.AppendUint16(inner, c.KDFID)
	inner = binary.BigEndian.AppendUint16(inner, c.AEADID)

	// Public name
	inner = append(inner, byte(len(c.PublicName)))
	inner = append(inner, []byte(c.PublicName)...)

	// Maximum name length
	if c.MaximumNameLength == 0 {
		c.MaximumNameLength = 64
	}
	inner = append(inner, c.MaximumNameLength)

	// Wrap config
	result := make([]byte, 4+len(inner))
	binary.BigEndian.PutUint16(result[0:2], 4) // Config type length
	binary.BigEndian.PutUint16(result[2:4], uint16(len(inner)))
	copy(result[4:], inner)

	return result, nil
}

// LoadConfigListFromFile loads an ECH configuration list from a file
func LoadConfigListFromFile(path string) (*ConfigList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Try to decode Base64
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		data = decoded
	}

	return ParseConfigList(data)
}

// LoadConfigListFromBase64 loads an ECH configuration list from a Base64 string
func LoadConfigListFromBase64(encoded string) (*ConfigList, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	return ParseConfigList(data)
}

// GenerateKey generates an ECH key pair
func GenerateKey(configID uint8, _ string) (*Key, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Key{
		ConfigID:   configID,
		PublicKey:  privateKey.PublicKey(),
		PrivateKey: privateKey,
	}, nil
}

// GenerateConfig generates an ECH configuration from a key
func (k *Key) GenerateConfig(publicName string) *Config {
	return &Config{
		Version:           0xfe,
		ConfigID:          k.ConfigID,
		KEMID:             HPKEDHKEMX25519,
		PublicKey:         k.PublicKey.Bytes(),
		KDFID:             HPKEHKDFSHA256,
		AEADID:            HPKEAES128GCM,
		PublicName:        publicName,
		MaximumNameLength: 64,
	}
}

// SavePrivateKey saves a private key to a file (PEM format)
func (k *Key) SavePrivateKey(path string) error {
	block := &pem.Block{
		Type:  "ECH PRIVATE KEY",
		Bytes: k.PrivateKey.Bytes(),
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	return pem.Encode(file, block)
}

// LoadPrivateKey loads a private key from a file
func LoadPrivateKey(path string, configID uint8) (*Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidKeyFormat
	}

	privateKey, err := ecdh.X25519().NewPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &Key{
		ConfigID:   configID,
		PublicKey:  privateKey.PublicKey(),
		PrivateKey: privateKey,
	}, nil
}

// SaveConfigList saves a configuration list to a file (Base64 format)
func SaveConfigList(path string, configs []Config) error {
	data, err := MarshalConfigList(configs)
	if err != nil {
		return err
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	return os.WriteFile(path, []byte(encoded), 0o644)
}

// ToBase64 encodes a configuration list to a Base64 string
func (l *ConfigList) ToBase64() (string, error) {
	data, err := MarshalConfigList(l.Configs)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// ToBytes serializes a configuration list to bytes
func (l *ConfigList) ToBytes() ([]byte, error) {
	return MarshalConfigList(l.Configs)
}

// LoadConfigListFromReader loads a configuration list from a Reader
func LoadConfigListFromReader(r io.Reader) (*ConfigList, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// Try to decode Base64
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		data = decoded
	}

	return ParseConfigList(data)
}

// PrintConfig prints configuration info (for debugging)
func PrintConfig(cfg *Config) {
	fmt.Printf("ECH Config:\n")
	fmt.Printf("  Version: 0x%02x\n", cfg.Version)
	fmt.Printf("  Config ID: %d\n", cfg.ConfigID)
	fmt.Printf("  KEM ID: 0x%04x\n", cfg.KEMID)
	fmt.Printf("  Public Key: %x...\n", cfg.PublicKey[:minInt(16, len(cfg.PublicKey))])
	fmt.Printf("  KDF ID: 0x%04x\n", cfg.KDFID)
	fmt.Printf("  AEAD ID: 0x%04x\n", cfg.AEADID)
	fmt.Printf("  Public Name: %s\n", cfg.PublicName)
	fmt.Printf("  Max Name Length: %d\n", cfg.MaximumNameLength)
}

// minInt returns the smaller of two integers (to avoid conflict with built-in min)
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
