package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lyimoexiao/gin-doh/internal/ech"
	"github.com/lyimoexiao/gin-doh/internal/proxy"
)

// DoHResolver DNS-over-HTTPS 解析器
type DoHResolver struct {
	BaseResolver
	url        string
	httpClient *http.Client
	proxyMgr   *proxy.Manager
	echConfig  *ech.ClientECHConfig // ECH 客户端配置
	echUsed    bool
}

// DoHResolverOption DoH 解析器选项
type DoHResolverOption func(*DoHResolver)

// WithECH 为 DoH 解析器添加 ECH 支持
func WithECH(echConfig *ech.ClientECHConfig) DoHResolverOption {
	return func(r *DoHResolver) {
		r.echConfig = echConfig
	}
}

// NewDoHResolver 创建 DoH 解析器
func NewDoHResolver(url string, timeout time.Duration, proxyMgr *proxy.Manager, opts ...DoHResolverOption) *DoHResolver {
	// 创建 TLS 配置
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// 创建 HTTP 客户端
	transport := &http.Transport{
		TLSClientConfig:  tlsConfig,
		IdleConnTimeout:  30 * time.Second,
		DisableKeepAlives: false,
		MaxIdleConns:      10,
	}

	// 如果有代理，配置代理
	if proxyMgr != nil && proxyMgr.Enabled() {
		transport.DialContext = proxyMgr.DialContext
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	resolver := &DoHResolver{
		BaseResolver: BaseResolver{
			protocol: "doh",
			address:  url,
			timeout:  timeout,
		},
		url:        url,
		httpClient: httpClient,
		proxyMgr:   proxyMgr,
	}

	// 应用选项
	for _, opt := range opts {
		opt(resolver)
	}

	// 如果有 ECH 配置，更新 TLS 配置
	if resolver.echConfig != nil && len(resolver.echConfig.ConfigList) > 0 {
		tlsConfig, _ = resolver.echConfig.GetTLSConfig(tlsConfig)
		transport.TLSClientConfig = tlsConfig
		resolver.echUsed = true
	}

	return resolver
}

// Resolve 执行 DNS 解析
func (r *DoHResolver) Resolve(ctx context.Context, query []byte) ([]byte, error) {
	// 创建 HTTP 请求
	req, err := http.NewRequestWithContext(ctx, "POST", r.url, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// 发送请求
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 检查状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	// 检查 Content-Type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/dns-message" {
		// 某些服务器可能不返回正确的 Content-Type，继续处理
	}

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// ResolveGET 使用 GET 方法解析 (某些 DoH 服务器要求)
func (r *DoHResolver) ResolveGET(ctx context.Context, query []byte) ([]byte, error) {
	// Base64 URL 编码查询
	encoded := base64.RawURLEncoding.EncodeToString(query)
	url := fmt.Sprintf("%s?dns=%s", r.url, encoded)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// String 返回服务器描述
func (r *DoHResolver) String() string {
	if r.echUsed {
		return "doh+ech://" + r.url
	}
	return "doh://" + r.url
}

// ECHUsed 返回是否使用了 ECH
func (r *DoHResolver) ECHUsed() bool {
	return r.echUsed
}