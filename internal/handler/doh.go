package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lyimoexiao/gin-doh/internal/logger"
	"github.com/lyimoexiao/gin-doh/internal/strategy"
	"github.com/lyimoexiao/gin-doh/internal/upstream"
	"github.com/lyimoexiao/gin-doh/pkg/dns"
)

// DoHHandler DoH 处理器
type DoHHandler struct {
	selector      strategy.Selector
	logger        *logger.Logger
	maxQuerySize  int
}

// NewDoHHandler 创建 DoH 处理器
func NewDoHHandler(selector strategy.Selector, logger *logger.Logger, maxQuerySize int) *DoHHandler {
	if maxQuerySize == 0 {
		maxQuerySize = 65535
	}
	return &DoHHandler{
		selector:     selector,
		logger:       logger,
		maxQuerySize: maxQuerySize,
	}
}

// Handle 处理 DNS 查询请求
func (h *DoHHandler) Handle(c *gin.Context) {
	start := time.Now()

	var query []byte
	var err error
	var queryName, queryTypeStr string

	// 根据请求方法解析查询
	switch c.Request.Method {
	case http.MethodPost:
		query, err = h.parsePostRequest(c)
	case http.MethodGet:
		query, queryName, queryTypeStr, err = h.parseGetRequestWithInfo(c)
	default:
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method not allowed"})
		return
	}

	if err != nil {
		h.handleError(c, err, start, queryName, queryTypeStr)
		return
	}

	// 验证查询大小
	if len(query) == 0 {
		h.handleError(c, ErrQueryEmpty, start, queryName, queryTypeStr)
		return
	}

	if len(query) > h.maxQuerySize {
		h.handleError(c, ErrQueryTooLarge, start, queryName, queryTypeStr)
		return
	}

	// 提取查询信息（如果还没有）
	if queryName == "" {
		queryName, _ = dns.ExtractQueryName(query)
	}
	queryType, _ := dns.ExtractQueryType(query)
	if queryTypeStr == "" {
		queryTypeStr = dns.TypeToString(queryType)
	}

	// 选择上游解析器
	resolver, err := h.selector.Select(c.Request.Context())
	if err != nil {
		h.handleError(c, err, start, queryName, queryTypeStr)
		return
	}

	// 执行查询
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	response, err := resolver.Resolve(ctx, query)
	if err != nil {
		h.selector.ReportFailure(resolver)
		h.handleError(c, err, start, queryName, queryTypeStr)
		return
	}

	// 报告成功并记录延迟
	latency := time.Since(start)
	h.selector.ReportSuccessWithLatency(resolver, latency)

	// 解析响应获取响应码
	rcode := 0
	if len(response) >= 4 {
		rcode = int(response[3] & 0x0F)
	}

	// 记录日志
	h.logRequest(c, queryName, queryTypeStr, resolver, dns.RcodeToString(rcode), latency.Milliseconds(), http.StatusOK)

	// 根据客户端 Accept 返回相应格式
	accept := c.GetHeader("Accept")
	if dns.IsAcceptJSON(accept) && c.Request.Method == http.MethodGet {
		// 返回 JSON 格式
		h.handleJSONResponse(c, response, start)
		return
	}

	// 返回 Wire Format
	c.Data(http.StatusOK, "application/dns-message", response)
}

// parsePostRequest 解析 POST 请求
func (h *DoHHandler) parsePostRequest(c *gin.Context) ([]byte, error) {
	contentType := c.GetHeader("Content-Type")
	if contentType != "application/dns-message" {
		return nil, ErrUnsupportedContentType
	}

	body, err := c.GetRawData()
	if err != nil {
		return nil, err
	}

	return body, nil
}

// parseGetRequest 解析 GET 请求
func (h *DoHHandler) parseGetRequest(c *gin.Context) ([]byte, error) {
	query, _, _, err := h.parseGetRequestWithInfo(c)
	return query, err
}

// parseGetRequestWithInfo 解析 GET 请求并返回查询信息
func (h *DoHHandler) parseGetRequestWithInfo(c *gin.Context) ([]byte, string, string, error) {
	// 检查是否是 Wire Format 参数
	dnsParam := c.Query("dns")
	if dnsParam != "" {
		// Wire Format GET 请求
		query, err := dns.DecodeBase64URL(dnsParam)
		if err != nil {
			return nil, "", "", ErrInvalidBase64
		}
		// Wire format 需要后续解析名称和类型
		return query, "", "", nil
	}

	// JSON Format GET 请求
	name := c.Query("name")
	if name == "" {
		return nil, "", "", ErrNameRequired
	}

	// 获取查询类型
	qtypeStr := c.DefaultQuery("type", "A")
	qtype := dns.StringToType(qtypeStr)
	if qtype == 0 {
		qtype = dns.TypeA
		qtypeStr = "A"
	}

	// 获取 DNSSEC 相关参数
	cd := c.Query("cd") == "true" || c.Query("cd") == "1"
	do := c.Query("do") == "true" || c.Query("do") == "1"

	// 构建 DNS 查询
	query, err := dns.BuildQueryWithOptions(name, qtype, cd, do)
	if err != nil {
		return nil, "", "", err
	}

	return query, name + ".", qtypeStr, nil
}

// handleJSONResponse 处理 JSON 响应
func (h *DoHHandler) handleJSONResponse(c *gin.Context, response []byte, start time.Time) {
	jsonResp, err := dns.WireToJSON(response)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse DNS response"})
		return
	}

	c.JSON(http.StatusOK, jsonResp)
}

// handleError 处理错误
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

// logRequest 记录请求日志
func (h *DoHHandler) logRequest(c *gin.Context, queryName, queryType string, resolver upstream.Resolver, rcode string, latency int64, status int) {
	upstreamAddr := ""
	upstreamProtocol := ""

	if resolver != nil {
		upstreamAddr = resolver.Address()
		upstreamProtocol = resolver.Protocol()
	}

	h.logger.LogDNSRequest(&logger.DNSRequestFields{
		Timestamp:        dns.CurrentTimestamp(),
		ClientIP:         c.ClientIP(),
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

// 错误定义
var (
	ErrQueryEmpty            = errors.New("dns query is empty")
	ErrQueryTooLarge         = errors.New("dns query is too large")
	ErrUnsupportedContentType = errors.New("unsupported content type")
	ErrInvalidBase64         = errors.New("invalid base64 encoding")
	ErrNameRequired          = errors.New("name parameter is required")
)

// HandleHealthCheck 健康检查端点
func (h *DoHHandler) HandleHealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
