package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lyimoexiao/gin-doh/internal/logger"
	"github.com/lyimoexiao/gin-doh/internal/strategy"
	"github.com/lyimoexiao/gin-doh/internal/upstream"
	"github.com/lyimoexiao/gin-doh/pkg/dns"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// mockSelector is a mock selector for testing
type mockSelector struct {
	resolver  upstream.Resolver
	selectErr error
	failures  int
	successes int
	latency   time.Duration
}

func (m *mockSelector) Select(_ context.Context) (upstream.Resolver, error) {
	if m.selectErr != nil {
		return nil, m.selectErr
	}
	return m.resolver, nil
}

func (m *mockSelector) ReportSuccess(_ upstream.Resolver) {
	m.successes++
}

func (m *mockSelector) ReportSuccessWithLatency(_ upstream.Resolver, latency time.Duration) {
	m.successes++
	m.latency = latency
}

func (m *mockSelector) ReportFailure(_ upstream.Resolver) {
	m.failures++
}

func (m *mockSelector) Name() string {
	return "mock"
}

// mockResolver is a mock resolver for testing
type mockResolver struct {
	response []byte
	err      error
}

func (m *mockResolver) Resolve(_ context.Context, _ []byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

func (m *mockResolver) Protocol() string {
	return "mock"
}

func (m *mockResolver) Address() string {
	return "mock://test"
}

func (m *mockResolver) String() string {
	return "mock://test"
}

// testLogger creates a test logger
func testLogger(t *testing.T) *logger.Logger {
	t.Helper()
	log, err := logger.New(&logger.Config{
		Level:  "error",
		Format: "json",
		Fields: []string{"timestamp"},
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	return log
}

// TestNewDoHHandler tests handler creation
func TestNewDoHHandler(t *testing.T) {
	selector := &mockSelector{}
	log := testLogger(t)

	handler := NewDoHHandler(selector, log, 0)
	if handler == nil {
		t.Fatal("Handler should not be nil")
	}

	// Test default max query size
	if handler.maxQuerySize != 65535 {
		t.Errorf("maxQuerySize = %d, want 65535", handler.maxQuerySize)
	}

	// Test custom max query size
	handler = NewDoHHandler(selector, log, 4096)
	if handler.maxQuerySize != 4096 {
		t.Errorf("maxQuerySize = %d, want 4096", handler.maxQuerySize)
	}
}

// TestHandleHealthCheck tests health check endpoint
func TestHandleHealthCheck(t *testing.T) {
	selector := &mockSelector{}
	log := testLogger(t)
	handler := NewDoHHandler(selector, log, 65535)

	router := gin.New()
	router.GET("/health", handler.HandleHealthCheck)

	req := httptest.NewRequest("GET", "/health", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
	}

	if w.Body.String() != `{"status":"ok"}` {
		t.Errorf("Body = %s, want {\"status\":\"ok\"}", w.Body.String())
	}
}

// TestHandleGETJSONQuery tests GET JSON query
func TestHandleGETJSONQuery(t *testing.T) {
	// Build a test DNS response
	testResponse, err := dns.BuildQuery("example.com", dns.TypeA)
	if err != nil {
		t.Fatalf("Failed to build test query: %v", err)
	}

	selector := &mockSelector{
		resolver: &mockResolver{response: testResponse},
	}
	log := testLogger(t)
	handler := NewDoHHandler(selector, log, 65535)

	router := gin.New()
	router.GET("/dns-query", handler.Handle)

	req := httptest.NewRequest("GET", "/dns-query?name=example.com&type=A", http.NoBody)
	req.Header.Set("Accept", "application/dns-json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
	}

	// Should return JSON response
	if w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %s", w.Header().Get("Content-Type"))
	}
}

// TestHandleGETWireFormat tests GET Wire Format query
func TestHandleGETWireFormat(t *testing.T) {
	testQuery, err := dns.BuildQuery("example.com", dns.TypeA)
	if err != nil {
		t.Fatalf("Failed to build test query: %v", err)
	}

	selector := &mockSelector{
		resolver: &mockResolver{response: testQuery},
	}
	log := testLogger(t)
	handler := NewDoHHandler(selector, log, 65535)

	router := gin.New()
	router.GET("/dns-query", handler.Handle)

	// Base64 URL encode the query
	encoded := base64.RawURLEncoding.EncodeToString(testQuery)
	req := httptest.NewRequest("GET", "/dns-query?dns="+encoded, http.NoBody)
	req.Header.Set("Accept", "application/dns-message")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
	}

	if w.Header().Get("Content-Type") != "application/dns-message" {
		t.Errorf("Content-Type = %s", w.Header().Get("Content-Type"))
	}
}

// TestHandlePOSTQuery tests POST query
func TestHandlePOSTQuery(t *testing.T) {
	testQuery, err := dns.BuildQuery("example.com", dns.TypeA)
	if err != nil {
		t.Fatalf("Failed to build test query: %v", err)
	}

	selector := &mockSelector{
		resolver: &mockResolver{response: testQuery},
	}
	log := testLogger(t)
	handler := NewDoHHandler(selector, log, 65535)

	router := gin.New()
	router.POST("/dns-query", handler.Handle)

	req := httptest.NewRequest("POST", "/dns-query", bytes.NewReader(testQuery))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
	}

	if w.Header().Get("Content-Type") != "application/dns-message" {
		t.Errorf("Content-Type = %s", w.Header().Get("Content-Type"))
	}
}

// TestHandleMissingNameParameter tests missing name parameter
func TestHandleMissingNameParameter(t *testing.T) {
	selector := &mockSelector{}
	log := testLogger(t)
	handler := NewDoHHandler(selector, log, 65535)

	router := gin.New()
	router.GET("/dns-query", handler.Handle)

	req := httptest.NewRequest("GET", "/dns-query?type=A", http.NoBody)
	req.Header.Set("Accept", "application/dns-json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestHandleInvalidBase64 tests invalid Base64 encoding
func TestHandleInvalidBase64(t *testing.T) {
	selector := &mockSelector{}
	log := testLogger(t)
	handler := NewDoHHandler(selector, log, 65535)

	router := gin.New()
	router.GET("/dns-query", handler.Handle)

	req := httptest.NewRequest("GET", "/dns-query?dns=invalid!base64", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestHandleUnsupportedContentType tests unsupported content type
func TestHandleUnsupportedContentType(t *testing.T) {
	selector := &mockSelector{}
	log := testLogger(t)
	handler := NewDoHHandler(selector, log, 65535)

	router := gin.New()
	router.POST("/dns-query", handler.Handle)

	req := httptest.NewRequest("POST", "/dns-query", bytes.NewReader([]byte("test")))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusUnsupportedMediaType)
	}
}

// TestHandleEmptyQuery tests empty query
func TestHandleEmptyQuery(t *testing.T) {
	selector := &mockSelector{}
	log := testLogger(t)
	handler := NewDoHHandler(selector, log, 65535)

	router := gin.New()
	router.POST("/dns-query", handler.Handle)

	req := httptest.NewRequest("POST", "/dns-query", bytes.NewReader([]byte{}))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestHandleQueryTooLarge tests query too large
func TestHandleQueryTooLarge(t *testing.T) {
	selector := &mockSelector{}
	log := testLogger(t)
	handler := NewDoHHandler(selector, log, 100) // Small max size

	router := gin.New()
	router.POST("/dns-query", handler.Handle)

	largeQuery := make([]byte, 200)
	req := httptest.NewRequest("POST", "/dns-query", bytes.NewReader(largeQuery))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}

// TestHandleNoResolvers tests no resolvers available
func TestHandleNoResolvers(t *testing.T) {
	selector := &mockSelector{
		selectErr: strategy.ErrNoResolvers,
	}
	log := testLogger(t)
	handler := NewDoHHandler(selector, log, 65535)

	router := gin.New()
	router.GET("/dns-query", handler.Handle)

	req := httptest.NewRequest("GET", "/dns-query?name=example.com&type=A", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

// TestHandleResolverFailure tests resolver failure
func TestHandleResolverFailure(t *testing.T) {
	selector := &mockSelector{
		resolver: &mockResolver{err: errors.New("timeout")},
	}
	log := testLogger(t)
	handler := NewDoHHandler(selector, log, 65535)

	router := gin.New()
	router.GET("/dns-query", handler.Handle)

	req := httptest.NewRequest("GET", "/dns-query?name=example.com&type=A", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusInternalServerError)
	}

	// Verify failure was reported
	if selector.failures != 1 {
		t.Errorf("Failures reported = %d, want 1", selector.failures)
	}
}

// TestHandleMethodNotAllowed tests method not allowed
func TestHandleMethodNotAllowed(t *testing.T) {
	selector := &mockSelector{}
	log := testLogger(t)
	handler := NewDoHHandler(selector, log, 65535)

	router := gin.New()
	router.PUT("/dns-query", handler.Handle)

	req := httptest.NewRequest("PUT", "/dns-query", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// TestHandleSuccessReport tests success reporting
func TestHandleSuccessReport(t *testing.T) {
	testResponse, err := dns.BuildQuery("example.com", dns.TypeA)
	if err != nil {
		t.Fatalf("Failed to build test query: %v", err)
	}

	selector := &mockSelector{
		resolver: &mockResolver{response: testResponse},
	}
	log := testLogger(t)
	handler := NewDoHHandler(selector, log, 65535)

	router := gin.New()
	router.GET("/dns-query", handler.Handle)

	req := httptest.NewRequest("GET", "/dns-query?name=example.com&type=A", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
	}

	// Verify success was reported
	if selector.successes != 1 {
		t.Errorf("Successes reported = %d, want 1", selector.successes)
	}
}

// TestErrorDefinitions tests error definitions
func TestErrorDefinitions(t *testing.T) {
	errors := []error{
		ErrQueryEmpty,
		ErrQueryTooLarge,
		ErrUnsupportedContentType,
		ErrInvalidBase64,
		ErrNameRequired,
	}

	for _, err := range errors {
		if err == nil {
			t.Error("Error should not be nil")
		}
		if err.Error() == "" {
			t.Error("Error message should not be empty")
		}
	}
}

// TestParseGetRequestWithInfo tests GET request parsing
func TestParseGetRequestWithInfo(t *testing.T) {
	// Create a test response for successful queries
	testResponse, err := dns.BuildQuery("example.com", dns.TypeA)
	if err != nil {
		t.Fatalf("Failed to build test query: %v", err)
	}

	tests := []struct {
		name       string
		url        string
		wantErr    bool
		wantStatus int
	}{
		{
			name:       "valid json query",
			url:        "/dns-query?name=example.com&type=A",
			wantErr:    false,
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing name",
			url:        "/dns-query?type=A",
			wantErr:    true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "valid wire format",
			url:        "/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
			wantErr:    false,
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid base64",
			url:        "/dns-query?dns=invalid!!",
			wantErr:    true,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector := &mockSelector{
				resolver: &mockResolver{response: testResponse},
			}
			log := testLogger(t)
			handler := NewDoHHandler(selector, log, 65535)

			router := gin.New()
			router.GET("/dns-query", handler.Handle)

			req := httptest.NewRequest("GET", tt.url, http.NoBody)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Status = %d, want %d, body: %s", w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

// TestHandleWithDNSSECOptions tests DNSSEC options
func TestHandleWithDNSSECOptions(t *testing.T) {
	testResponse, err := dns.BuildQuery("example.com", dns.TypeA)
	if err != nil {
		t.Fatalf("Failed to build test query: %v", err)
	}

	selector := &mockSelector{
		resolver: &mockResolver{response: testResponse},
	}
	log := testLogger(t)
	handler := NewDoHHandler(selector, log, 65535)

	router := gin.New()
	router.GET("/dns-query", handler.Handle)

	// Test with DNSSEC options
	req := httptest.NewRequest("GET", "/dns-query?name=example.com&type=A&cd=true&do=true", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Should succeed
	if w.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestHandleMultipleQueryTypes tests different query types
func TestHandleMultipleQueryTypes(t *testing.T) {
	testResponse, _ := dns.BuildQuery("example.com", dns.TypeA)

	selector := &mockSelector{
		resolver: &mockResolver{response: testResponse},
	}
	log := testLogger(t)
	handler := NewDoHHandler(selector, log, 65535)

	types := []string{"A", "AAAA", "MX", "TXT", "CNAME", "NS"}

	for _, qtype := range types {
		t.Run(qtype, func(t *testing.T) {
			router := gin.New()
			router.GET("/dns-query", handler.Handle)

			req := httptest.NewRequest("GET", "/dns-query?name=example.com&type="+qtype, http.NoBody)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Type %s: Status = %d, want %d", qtype, w.Code, http.StatusOK)
			}
		})
	}
}
