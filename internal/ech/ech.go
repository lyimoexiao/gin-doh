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

// ECH 相关常量
const (
	// ECH 配置版本
	ECHConfigVersion = 0xfe0d

	// HPKE KEM 标识符
	HPKEDHKEMX25519 uint16 = 0x0020

	// HPKE KDF 标识符
	HPKEHKDFSHA256 uint16 = 0x0001

	// HPKE AEAD 标识符
	HPKEAES128GCM       uint16 = 0x0001
	HPKEAES256GCM       uint16 = 0x0002
	HPKEChaCha20Poly1305 uint16 = 0x0003
)

// Config ECH 配置结构 (用于服务端和客户端)
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

// ConfigList ECH 配置列表
type ConfigList struct {
	Configs []Config
}

// Key ECH 密钥对
type Key struct {
	ConfigID  uint8
	PublicKey *ecdh.PublicKey
	PrivateKey *ecdh.PrivateKey
}

var (
	ErrInvalidECHConfig     = errors.New("invalid ECH config")
	ErrInvalidECHConfigList = errors.New("invalid ECH config list")
	ErrUnsupportedKEM       = errors.New("unsupported KEM algorithm")
	ErrInvalidKeyFormat     = errors.New("invalid key format")
)

// ParseConfigList 解析 ECH 配置列表
func ParseConfigList(data []byte) (*ConfigList, error) {
	if len(data) < 2 {
		return nil, ErrInvalidECHConfigList
	}

	// 读取配置列表长度
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

		// 读取配置长度
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

// parseConfig 解析单个 ECH 配置
func parseConfig(data []byte) (*Config, error) {
	if len(data) < 10 {
		return nil, ErrInvalidECHConfig
	}

	offset := 0

	// 读取配置类型长度 (2 bytes)
	configTypeLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// 读取配置长度 (2 bytes)
	configLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	_ = configTypeLen // 忽略配置类型长度

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

// parseConfigInner 解析 ECH 配置内部结构
func parseConfigInner(data []byte) (*Config, error) {
	if len(data) < 8 {
		return nil, ErrInvalidECHConfig
	}

	offset := 0
	cfg := &Config{}

	// 版本 (2 bytes)
	cfg.Version = data[offset]
	offset += 2 // 跳过版本 (uint16)

	// 配置 ID (1 byte)
	cfg.ConfigID = data[offset]
	offset++

	// KEM ID (2 bytes)
	cfg.KEMID = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 公钥长度 (2 bytes)
	pubKeyLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+pubKeyLen > len(data) {
		return nil, ErrInvalidECHConfig
	}

	// 公钥
	cfg.PublicKey = make([]byte, pubKeyLen)
	copy(cfg.PublicKey, data[offset:offset+pubKeyLen])
	offset += pubKeyLen

	// HPKE 套件长度 (2 bytes)
	suiteLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// 读取 HPKE 套件 (取第一个)
	if suiteLen > 0 && offset+4 <= len(data) {
		cfg.KDFID = binary.BigEndian.Uint16(data[offset : offset+2])
		cfg.AEADID = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	}
	offset += suiteLen * 4

	// 公共名称长度 (1 byte)
	if offset >= len(data) {
		return nil, ErrInvalidECHConfig
	}
	nameLen := int(data[offset])
	offset++

	if offset+nameLen > len(data) {
		return nil, ErrInvalidECHConfig
	}

	// 公共名称
	cfg.PublicName = string(data[offset : offset+nameLen])
	offset += nameLen

	// 最大名称长度 (1 byte)
	if offset < len(data) {
		cfg.MaximumNameLength = data[offset]
	}

	return cfg, nil
}

// MarshalConfigList 序列化 ECH 配置列表
func MarshalConfigList(configs []Config) ([]byte, error) {
	var configBytes []byte

	for _, cfg := range configs {
		b, err := cfg.marshal()
		if err != nil {
			return nil, err
		}
		configBytes = append(configBytes, b...)
	}

	// 添加总长度前缀
	result := make([]byte, 2+len(configBytes))
	binary.BigEndian.PutUint16(result[0:2], uint16(len(configBytes)))
	copy(result[2:], configBytes)

	return result, nil
}

// marshal 序列化单个 ECH 配置
func (c *Config) marshal() ([]byte, error) {
	var inner []byte

	// 版本
	inner = append(inner, 0x00, byte(c.Version))

	// 配置 ID
	inner = append(inner, c.ConfigID)

	// KEM ID
	inner = binary.BigEndian.AppendUint16(inner, c.KEMID)

	// 公钥长度和公钥
	inner = binary.BigEndian.AppendUint16(inner, uint16(len(c.PublicKey)))
	inner = append(inner, c.PublicKey...)

	// HPKE 套件 (KDF ID + AEAD ID)
	inner = binary.BigEndian.AppendUint16(inner, 4) // 一个套件
	inner = binary.BigEndian.AppendUint16(inner, c.KDFID)
	inner = binary.BigEndian.AppendUint16(inner, c.AEADID)

	// 公共名称
	inner = append(inner, byte(len(c.PublicName)))
	inner = append(inner, []byte(c.PublicName)...)

	// 最大名称长度
	if c.MaximumNameLength == 0 {
		c.MaximumNameLength = 64
	}
	inner = append(inner, c.MaximumNameLength)

	// 包装配置
	result := make([]byte, 4+len(inner))
	binary.BigEndian.PutUint16(result[0:2], 4) // 配置类型长度
	binary.BigEndian.PutUint16(result[2:4], uint16(len(inner)))
	copy(result[4:], inner)

	return result, nil
}

// LoadConfigListFromFile 从文件加载 ECH 配置列表
func LoadConfigListFromFile(path string) (*ConfigList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// 尝试解码 Base64
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		data = decoded
	}

	return ParseConfigList(data)
}

// LoadConfigListFromBase64 从 Base64 字符串加载 ECH 配置列表
func LoadConfigListFromBase64(encoded string) (*ConfigList, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	return ParseConfigList(data)
}

// GenerateKey 生成 ECH 密钥对
func GenerateKey(configID uint8, publicName string) (*Key, error) {
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

// GenerateConfig 从密钥生成 ECH 配置
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

// SavePrivateKey 保存私钥到文件 (PEM 格式)
func (k *Key) SavePrivateKey(path string) error {
	block := &pem.Block{
		Type:  "ECH PRIVATE KEY",
		Bytes: k.PrivateKey.Bytes(),
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, block)
}

// LoadPrivateKey 从文件加载私钥
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

// SaveConfigList 保存配置列表到文件 (Base64 格式)
func SaveConfigList(path string, configs []Config) error {
	data, err := MarshalConfigList(configs)
	if err != nil {
		return err
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	return os.WriteFile(path, []byte(encoded), 0644)
}

// ToBase64 将配置列表编码为 Base64 字符串
func (l *ConfigList) ToBase64() (string, error) {
	data, err := MarshalConfigList(l.Configs)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// ToBytes 将配置列表序列化为字节
func (l *ConfigList) ToBytes() ([]byte, error) {
	return MarshalConfigList(l.Configs)
}

// LoadConfigListFromReader 从 Reader 加载配置列表
func LoadConfigListFromReader(r io.Reader) (*ConfigList, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// 尝试解码 Base64
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		data = decoded
	}

	return ParseConfigList(data)
}

// PrintConfig 打印配置信息 (用于调试)
func PrintConfig(cfg *Config) {
	fmt.Printf("ECH Config:\n")
	fmt.Printf("  Version: 0x%02x\n", cfg.Version)
	fmt.Printf("  Config ID: %d\n", cfg.ConfigID)
	fmt.Printf("  KEM ID: 0x%04x\n", cfg.KEMID)
	fmt.Printf("  Public Key: %x...\n", cfg.PublicKey[:min(16, len(cfg.PublicKey))])
	fmt.Printf("  KDF ID: 0x%04x\n", cfg.KDFID)
	fmt.Printf("  AEAD ID: 0x%04x\n", cfg.AEADID)
	fmt.Printf("  Public Name: %s\n", cfg.PublicName)
	fmt.Printf("  Max Name Length: %d\n", cfg.MaximumNameLength)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
