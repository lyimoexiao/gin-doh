// Package upstream provides DNS resolver implementations for various protocols.
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

// DoHResolver is a DNS-over-HTTPS resolver
type DoHResolver struct {
	BaseResolver
	url        string
	httpClient *http.Client
	proxyMgr   *proxy.Manager
	echConfig  *ech.ClientECHConfig
	echUsed    bool
}

// DoHResolverOption is a DoH resolver option
type DoHResolverOption func(*DoHResolver)

// WithECH adds ECH support for the DoH resolver
func WithECH(echConfig *ech.ClientECHConfig) DoHResolverOption {
	return func(r *DoHResolver) {
		r.echConfig = echConfig
	}
}

// NewDoHResolver creates a new DoH resolver
func NewDoHResolver(url string, timeout time.Duration, proxyMgr *proxy.Manager, opts ...DoHResolverOption) *DoHResolver {
	// Create TLS config
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Create HTTP client
	transport := &http.Transport{
		TLSClientConfig:   tlsConfig,
		IdleConnTimeout:   30 * time.Second,
		DisableKeepAlives: false,
		MaxIdleConns:      10,
	}

	// Configure proxy if available
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

	// Apply options
	for _, opt := range opts {
		opt(resolver)
	}

	// Update TLS config if ECH is configured
	if resolver.echConfig != nil && len(resolver.echConfig.ConfigList) > 0 {
		tlsConfig, _ = resolver.echConfig.GetTLSConfig(tlsConfig)
		transport.TLSClientConfig = tlsConfig
		resolver.echUsed = true
	}

	return resolver
}

// Resolve performs DNS resolution
func (r *DoHResolver) Resolve(ctx context.Context, query []byte) ([]byte, error) {
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", r.url, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// Send request
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// ResolveGET resolves using GET method (some DoH servers require this)
func (r *DoHResolver) ResolveGET(ctx context.Context, query []byte) ([]byte, error) {
	// Base64 URL encode query
	encoded := base64.RawURLEncoding.EncodeToString(query)
	url := fmt.Sprintf("%s?dns=%s", r.url, encoded)

	req, err := http.NewRequestWithContext(ctx, "GET", url, http.NoBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// String returns server description
func (r *DoHResolver) String() string {
	if r.echUsed {
		return "doh+ech://" + r.url
	}
	return "doh://" + r.url
}

// ECHUsed returns whether ECH is used
func (r *DoHResolver) ECHUsed() bool {
	return r.echUsed
}
