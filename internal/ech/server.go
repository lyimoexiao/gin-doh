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

// ServerECHConfig 服务端 ECH 配置管理器
type ServerECHConfig struct {
	Keys        []Key
	ConfigList  []byte // 用于发送给客户端的配置列表
	RetryConfig []byte // 重试配置列表
	PublicName  string
}

// NewServerECHConfig 创建服务端 ECH 配置
func NewServerECHConfig(publicName string) *ServerECHConfig {
	return &ServerECHConfig{
		PublicName: publicName,
	}
}

// AddKey 添加 ECH 密钥
func (s *ServerECHConfig) AddKey(key *Key) error {
	s.Keys = append(s.Keys, *key)
	return s.rebuildConfigList()
}

// GenerateAndAddKey 生成并添加新密钥
func (s *ServerECHConfig) GenerateAndAddKey(configID uint8) error {
	key, err := GenerateKey(configID, s.PublicName)
	if err != nil {
		return err
	}
	return s.AddKey(key)
}

// rebuildConfigList 重建配置列表
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

// LoadKeysFromFile 从文件加载密钥
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

// LoadConfigListFromFile 从文件加载配置列表
func (s *ServerECHConfig) LoadConfigListFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// 尝试解码 Base64
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		data = decoded
	}

	s.ConfigList = data
	return nil
}

// LoadRetryConfigFromFile 从文件加载重试配置
func (s *ServerECHConfig) LoadRetryConfigFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// 尝试解码 Base64
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		data = decoded
	}

	s.RetryConfig = data
	return nil
}

// GetTLSConfig 获取 ECH 相关的 TLS 配置
// 注意：Go 标准库目前仅支持客户端 ECH，服务端 ECH 支持有限
func (s *ServerECHConfig) GetTLSConfig(baseConfig *tls.Config) (*tls.Config, error) {
	if baseConfig == nil {
		baseConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}

	// Go 1.25+ 服务端 ECH 支持需要使用 EncryptedClientHelloKeys
	// 这里我们准备配置，实际支持取决于 Go 版本

	// 设置最小版本为 TLS 1.3
	baseConfig.MinVersion = tls.VersionTLS13

	return baseConfig, nil
}

// ClientECHConfig 客户端 ECH 配置
type ClientECHConfig struct {
	ConfigList []byte
}

// NewClientECHConfig 创建客户端 ECH 配置
func NewClientECHConfig() *ClientECHConfig {
	return &ClientECHConfig{}
}

// LoadConfigListFromFile 从文件加载配置列表
func (c *ClientECHConfig) LoadConfigListFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// 尝试解码 Base64
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		data = decoded
	}

	c.ConfigList = data
	return nil
}

// LoadConfigListFromBase64 从 Base64 加载配置列表
func (c *ClientECHConfig) LoadConfigListFromBase64(encoded string) error {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	c.ConfigList = data
	return nil
}

// GetTLSConfig 获取带有 ECH 配置的 TLS 客户端配置
func (c *ClientECHConfig) GetTLSConfig(baseConfig *tls.Config) (*tls.Config, error) {
	if baseConfig == nil {
		baseConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}

	if len(c.ConfigList) > 0 {
		// Go 1.23+ 支持 EncryptedClientHelloConfigList
		baseConfig.EncryptedClientHelloConfigList = c.ConfigList
	}

	return baseConfig, nil
}

// ECHKeyProvider ECH 密钥提供者接口
type ECHKeyProvider interface {
	// GetKey 根据配置 ID 获取密钥
	GetKey(configID uint8) (*Key, bool)
	// GetAllKeys 获取所有密钥
	GetAllKeys() []Key
}

// GetKey 根据 ID 获取密钥
func (s *ServerECHConfig) GetKey(configID uint8) (*Key, bool) {
	for i := range s.Keys {
		if s.Keys[i].ConfigID == configID {
			return &s.Keys[i], true
		}
	}
	return nil, false
}

// GetAllKeys 获取所有密钥
func (s *ServerECHConfig) GetAllKeys() []Key {
	return s.Keys
}

// PEMBlock PEM 块结构
type PEMBlock struct {
	Type  string
	Bytes []byte
}

// encodePEM 编码 PEM 块
func encodePEM(block *PEMBlock) []byte {
	return []byte(fmt.Sprintf("-----BEGIN %s-----\n%s-----END %s-----\n",
		block.Type,
		base64.StdEncoding.EncodeToString(block.Bytes),
		block.Type))
}

// GenerateKeyPair 生成 ECH 密钥对并保存到文件
func GenerateKeyPair(configID uint8, publicKeyFile, privateKeyFile string) error {
	key, err := GenerateKey(configID, "")
	if err != nil {
		return err
	}

	// 保存私钥
	if err := key.SavePrivateKey(privateKeyFile); err != nil {
		return err
	}

	// 保存公钥
	pubKeyBlock := &PEMBlock{
		Type:  "ECH PUBLIC KEY",
		Bytes: key.PublicKey.Bytes(),
	}
	pubKeyData := encodePEM(pubKeyBlock)
	return os.WriteFile(publicKeyFile, pubKeyData, 0644)
}

// ECHGreaseConfig ECH GREASE 配置 (用于发送假 ECH 扩展)
type ECHGreaseConfig struct {
	Enabled bool
}

// NewECHGreaseConfig 创建 GREASE 配置
func NewECHGreaseConfig() *ECHGreaseConfig {
	return &ECHGreaseConfig{
		Enabled: true,
	}
}

// GenerateGreaseECH 生成 GREASE ECH 扩展数据
func (g *ECHGreaseConfig) GenerateGreaseECH() []byte {
	// 生成随机数据模拟 ECH 扩展
	// 实际实现应该遵循 draft-ietf-tls-esni
	data := make([]byte, 128)
	rand.Read(data)
	return data
}

// ParseClientHelloECH 从 ClientHello 解析 ECH 信息
func ParseClientHelloECH(hello []byte) (hasECH bool, isInner bool, configID uint8, err error) {
	// 简化的 ECH 扩展解析
	// 实际实现需要完整的 TLS 扩展解析

	if len(hello) < 43 {
		return false, false, 0, nil
	}

	// 查找 ECH 扩展 (扩展类型 0xfe0d)
	// 这里只是示意，实际需要完整解析

	return false, false, 0, nil
}

// DecryptClientHello 解密 ECH ClientHello (服务端使用)
func DecryptClientHello(encryptedHello []byte, key *Key) ([]byte, error) {
	// HPKE 解密实现
	// 这需要完整的 HPKE 实现

	return nil, fmt.Errorf("ECH decryption not implemented")
}

// EncryptedClientHelloKey 用于 Go 1.25+ 的 ECH 密钥格式
type EncryptedClientHelloKey struct {
	ID         uint8
	PrivateKey *ecdh.PrivateKey
}

// ToGoECHKey 转换为 Go 标准库的 ECH 密钥格式
func (k *Key) ToGoECHKey() *EncryptedClientHelloKey {
	return &EncryptedClientHelloKey{
		ID:         k.ConfigID,
		PrivateKey: k.PrivateKey,
	}
}

// ParseEncryptedClientHelloConfigList 解析 ECH 配置列表 (简化版)
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
