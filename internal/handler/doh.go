// Package handler provides HTTP request handlers for the DoH server.
package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lyimoexiao/gin-doh/internal/logger"
	"github.com/lyimoexiao/gin-doh/internal/middleware"
	"github.com/lyimoexiao/gin-doh/internal/strategy"
	"github.com/lyimoexiao/gin-doh/internal/upstream"
	"github.com/lyimoexiao/gin-doh/pkg/dns"
)

const (
	// contentTypeDNSMessage is the MIME type for DNS wire format
	contentTypeDNSMessage = "application/dns-message"
)

// DoHHandler handles DNS-over-HTTPS requests
type DoHHandler struct {
	selector     strategy.Selector
	log          *logger.Logger
	maxQuerySize int
}

// NewDoHHandler creates a new DoH handler
func NewDoHHandler(selector strategy.Selector, log *logger.Logger, maxQuerySize int) *DoHHandler {
	if maxQuerySize == 0 {
		maxQuerySize = 65535
	}
	return &DoHHandler{
		selector:     selector,
		log:          log,
		maxQuerySize: maxQuerySize,
	}
}

// Handle handles DNS query requests
func (h *DoHHandler) Handle(c *gin.Context) {
	start := time.Now()

	// Parse and validate request
	query, queryName, queryTypeStr, ecsInjected, err := h.parseAndValidate(c, start)
	if err != nil {
		return
	}

	// Execute DNS query
	response, resolver, rcode, latency, err := h.executeQuery(c, query, queryName, ecsInjected)
	if err != nil {
		h.handleError(c, err, start, queryName, queryTypeStr)
		return
	}

	// Log request
	h.logRequest(c, queryName, queryTypeStr, resolver, dns.RcodeToString(rcode), latency.Milliseconds(), http.StatusOK)

	// Return response
	h.sendResponse(c, response)
}

// parseAndValidate parses and validates the DNS request
func (h *DoHHandler) parseAndValidate(c *gin.Context, start time.Time) (query []byte, queryName, queryTypeStr string, ecsInjected bool, err error) {
	// Parse query based on request method
	switch c.Request.Method {
	case http.MethodPost:
		query, err = h.parsePostRequest(c)
	case http.MethodGet:
		query, queryName, queryTypeStr, ecsInjected, err = h.parseGetRequestWithInfo(c)
	default:
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method not allowed"})
		return nil, "", "", false, ErrMethodNotAllowed
	}

	if err != nil {
		h.handleError(c, err, start, queryName, queryTypeStr)
		return nil, "", "", false, err
	}

	// Validate query size
	if len(query) == 0 {
		h.handleError(c, ErrQueryEmpty, start, queryName, queryTypeStr)
		return nil, "", "", false, ErrQueryEmpty
	}

	if len(query) > h.maxQuerySize {
		h.handleError(c, ErrQueryTooLarge, start, queryName, queryTypeStr)
		return nil, "", "", false, ErrQueryTooLarge
	}

	// Extract query info if not already extracted
	if queryName == "" {
		queryName, _ = dns.ExtractQueryName(query)
	}
	queryType, _ := dns.ExtractQueryType(query)
	if queryTypeStr == "" {
		queryTypeStr = dns.TypeToString(queryType)
	}

	return query, queryName, queryTypeStr, ecsInjected, nil
}

// executeQuery executes the DNS query and returns the response
func (h *DoHHandler) executeQuery(c *gin.Context, query []byte, _ string, ecsInjected bool) (response []byte, resolver upstream.Resolver, rcode int, latency time.Duration, err error) {
	// For POST and Wire Format GET, try to inject ECS from client IP
	if !ecsInjected {
		clientIP := middleware.GetRealIP(c)
		ecs := dns.ClientIPToECS(clientIP)
		if ecs != "" {
			modifiedQuery, injectErr := dns.InjectECS(query, ecs)
			if injectErr == nil {
				query = modifiedQuery
			}
		}
	}

	// Select upstream resolver
	resolver, err = h.selector.Select(c.Request.Context())
	if err != nil {
		return
	}

	// Execute query
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	start := time.Now()
	response, err = resolver.Resolve(ctx, query)
	if err != nil {
		h.selector.ReportFailure(resolver)
		return
	}

	// Report success and record latency
	latency = time.Since(start)
	h.selector.ReportSuccessWithLatency(resolver, latency)

	// Parse response code
	rcode = 0
	if len(response) >= 4 {
		rcode = int(response[3] & 0x0F)
	}

	return
}

// sendResponse sends the DNS response to the client
func (h *DoHHandler) sendResponse(c *gin.Context, response []byte) {
	accept := c.GetHeader("Accept")
	if dns.IsAcceptJSON(accept) && c.Request.Method == http.MethodGet {
		h.handleJSONResponse(c, response)
		return
	}
	c.Data(http.StatusOK, contentTypeDNSMessage, response)
}

// parsePostRequest parses a POST request
func (h *DoHHandler) parsePostRequest(c *gin.Context) ([]byte, error) {
	contentType := c.GetHeader("Content-Type")
	if contentType != contentTypeDNSMessage {
		return nil, ErrUnsupportedContentType
	}

	body, err := c.GetRawData()
	if err != nil {
		return nil, err
	}

	return body, nil
}

// parseGetRequestWithInfo parses a GET request and returns query info
// Returns: query, queryName, queryType, ecsInjected, error
func (h *DoHHandler) parseGetRequestWithInfo(c *gin.Context) (query []byte, queryName, queryType string, ecsInjected bool, err error) {
	// Check if it's a Wire Format parameter
	dnsParam := c.Query("dns")
	if dnsParam != "" {
		// Wire Format GET request
		query, err = dns.DecodeBase64URL(dnsParam)
		if err != nil {
			return nil, "", "", false, ErrInvalidBase64
		}
		// For wire format, ECS injection will be handled in Handle()
		return query, "", "", false, nil
	}

	// JSON Format GET request
	name := c.Query("name")
	if name == "" {
		return nil, "", "", false, ErrNameRequired
	}

	// Get query type
	qtypeStr := c.DefaultQuery("type", "A")
	qtype := dns.StringToType(qtypeStr)
	if qtype == 0 {
		qtype = dns.TypeA
		qtypeStr = "A"
	}

	// Get DNSSEC parameters
	cd := c.Query("cd") == "true" || c.Query("cd") == "1"
	do := c.Query("do") == "true" || c.Query("do") == "1"

	// Get ECS parameter
	ecs := c.Query("ecs")
	if ecs == "" {
		ecs = c.Query("subnet") // Alternative parameter name (like Google DoH)
	}

	// If no ECS provided, auto-detect from client IP
	if ecs == "" {
		clientIP := middleware.GetRealIP(c)
		ecs = dns.ClientIPToECS(clientIP)
		if ecs != "" {
			ecsInjected = true
		}
	}

	// Build DNS query
	query, err = dns.BuildQueryWithOpts(name, qtype, dns.QueryOptions{
		CD:  cd,
		DO:  do,
		ECS: ecs,
	})
	if err != nil {
		return nil, "", "", false, err
	}

	return query, name + ".", qtypeStr, ecsInjected, nil
}

// handleJSONResponse handles JSON response
func (h *DoHHandler) handleJSONResponse(c *gin.Context, response []byte) {
	jsonResp, err := dns.WireToJSON(response)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse DNS response"})
		return
	}

	c.JSON(http.StatusOK, jsonResp)
}

// handleError handles errors
func (h *DoHHandler) handleError(c *gin.Context, err error, start time.Time, queryName, queryType string) {
	var status int
	var errMsg string

	switch {
	case errors.Is(err, ErrQueryEmpty):
		status = http.StatusBadRequest
		errMsg = "DNS query is empty"
	case errors.Is(err, ErrQueryTooLarge):
		status = http.StatusRequestEntityTooLarge
		errMsg = "DNS query is too large"
	case errors.Is(err, ErrUnsupportedContentType):
		status = http.StatusUnsupportedMediaType
		errMsg = "unsupported content type"
	case errors.Is(err, ErrInvalidBase64):
		status = http.StatusBadRequest
		errMsg = "invalid base64 encoding"
	case errors.Is(err, ErrNameRequired):
		status = http.StatusBadRequest
		errMsg = "name parameter is required"
	case errors.Is(err, upstream.ErrUnsupportedProtocol):
		status = http.StatusInternalServerError
		errMsg = "unsupported upstream protocol"
	case errors.Is(err, strategy.ErrNoResolvers):
		status = http.StatusServiceUnavailable
		errMsg = "no upstream resolvers available"
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
		errMsg = "upstream DNS timeout"
	default:
		status = http.StatusInternalServerError
		errMsg = err.Error()
	}

	latency := time.Since(start).Milliseconds()
	h.logRequest(c, queryName, queryType, nil, "ERROR", latency, status)

	c.JSON(status, gin.H{"error": errMsg})
}

// logRequest logs request information
func (h *DoHHandler) logRequest(c *gin.Context, queryName, queryType string, resolver upstream.Resolver, rcode string, latency int64, status int) {
	upstreamAddr := ""
	upstreamProtocol := ""

	if resolver != nil {
		upstreamAddr = resolver.Address()
		upstreamProtocol = resolver.Protocol()
	}

	h.log.LogDNSRequest(&logger.DNSRequestFields{
		Timestamp:        dns.CurrentTimestamp(),
		ClientIP:         middleware.GetRealIP(c),
		Method:           c.Request.Method,
		Path:             c.Request.URL.Path,
		QueryName:        queryName,
		QueryType:        queryType,
		Upstream:         upstreamAddr,
		UpstreamProtocol: upstreamProtocol,
		ResponseCode:     rcode,
		LatencyMs:        latency,
		Status:           status,
	})
}

// Error definitions
var (
	ErrQueryEmpty             = errors.New("dns query is empty")
	ErrQueryTooLarge          = errors.New("dns query is too large")
	ErrUnsupportedContentType = errors.New("unsupported content type")
	ErrInvalidBase64          = errors.New("invalid base64 encoding")
	ErrNameRequired           = errors.New("name parameter is required")
	ErrMethodNotAllowed       = errors.New("method not allowed")
)

// HandleHealthCheck handles health check endpoint
func (h *DoHHandler) HandleHealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
