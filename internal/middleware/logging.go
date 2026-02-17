// Package middleware provides HTTP middleware for the DoH server.
package middleware

import (
	"net"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lyimoexiao/gin-doh/internal/logger"
)

// LoggingMiddleware logs access requests
func LoggingMiddleware(log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		// Process request
		c.Next()

		// Log access
		latency := time.Since(start)
		status := c.Writer.Status()
		clientIP := c.ClientIP()

		log.Infow("access",
			"timestamp", start.UTC().Format(time.RFC3339),
			"client_ip", clientIP,
			"method", method,
			"path", path,
			"status", status,
			"latency_ms", latency.Milliseconds(),
			"user_agent", c.Request.UserAgent(),
		)
	}
}

// RecoveryMiddleware recovers from panics
func RecoveryMiddleware(log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.Errorw("panic recovered",
					"timestamp", time.Now().UTC().Format(time.RFC3339),
					"client_ip", c.ClientIP(),
					"method", c.Request.Method,
					"path", c.Request.URL.Path,
					"error", err,
				)

				c.AbortWithStatusJSON(500, gin.H{
					"error": "internal server error",
				})
			}
		}()
		c.Next()
	}
}

// CORSMiddleware handles CORS
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
		c.Writer.Header().Set("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// RateLimitMiddleware rate limiting (placeholder)
func RateLimitMiddleware(_, _ int) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}

// RequestIDMiddleware adds request ID
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		c.Set("request_id", requestID)
		c.Writer.Header().Set("X-Request-ID", requestID)
		c.Next()
	}
}

// RealIPMiddleware extracts real client IP from proxy headers
// Supports X-Forwarded-For, X-Real-IP, and X-Client-IP headers
// Only trusts headers from configured trusted proxies
func RealIPMiddleware(trustedProxies []string, customHeader string) gin.HandlerFunc {
	// Parse trusted proxies into CIDR networks
	trustedNets := make([]*net.IPNet, 0, len(trustedProxies))
	for _, proxy := range trustedProxies {
		// Handle CIDR notation
		if strings.Contains(proxy, "/") {
			_, ipNet, err := net.ParseCIDR(proxy)
			if err == nil {
				trustedNets = append(trustedNets, ipNet)
			}
		} else {
			// Single IP - convert to /32 or /128
			ip := net.ParseIP(proxy)
			if ip != nil {
				if ip.To4() != nil {
					_, ipNet, _ := net.ParseCIDR(proxy + "/32")
					trustedNets = append(trustedNets, ipNet)
				} else {
					_, ipNet, _ := net.ParseCIDR(proxy + "/128")
					trustedNets = append(trustedNets, ipNet)
				}
			}
		}
	}

	return func(c *gin.Context) {
		// Get the direct remote address
		remoteIP := net.ParseIP(c.ClientIP())
		if remoteIP == nil {
			c.Next()
			return
		}

		// Check if the remote address is a trusted proxy (or trust all if no trusted proxies configured)
		isTrusted := len(trustedNets) == 0
		for _, ipNet := range trustedNets {
			if ipNet.Contains(remoteIP) {
				isTrusted = true
				break
			}
		}

		if !isTrusted {
			// Not from a trusted proxy, don't trust headers
			c.Next()
			return
		}

		// Try to get real IP from headers (in order of preference)
		realIP := extractRealIP(c, customHeader)
		if realIP != "" {
			// Store the original remote address
			c.Set("original_remote_addr", c.ClientIP())
			// Store the extracted real IP for use by handlers
			c.Set("real_ip", realIP)
			// Update the request's RemoteAddr for compatibility
			c.Request.RemoteAddr = realIP
		}

		c.Next()
	}
}

// GetRealIP retrieves the real client IP from gin context
// Falls back to c.ClientIP() if not set
func GetRealIP(c *gin.Context) string {
	if realIP, exists := c.Get("real_ip"); exists {
		if ip, ok := realIP.(string); ok {
			return ip
		}
	}
	return c.ClientIP()
}

// extractRealIP extracts the real client IP from proxy headers
func extractRealIP(c *gin.Context, customHeader string) string {
	// Try custom header first if specified
	if customHeader != "" {
		if ip := extractIPFromHeader(c, customHeader); ip != "" {
			return ip
		}
	}

	// Try headers in order of preference
	headers := []string{"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "True-Client-IP"}
	for _, header := range headers {
		if ip := extractIPFromHeader(c, header); ip != "" {
			// Special handling for X-Forwarded-For
			if header == "X-Forwarded-For" {
				return extractFirstIP(ip)
			}
			return ip
		}
	}

	return ""
}

// extractIPFromHeader extracts and validates IP from a single header
func extractIPFromHeader(c *gin.Context, header string) string {
	value := c.GetHeader(header)
	if value == "" {
		return ""
	}
	ip := strings.TrimSpace(value)
	if net.ParseIP(ip) != nil {
		return ip
	}
	return ""
}

// extractFirstIP extracts the first valid IP from a comma-separated list
func extractFirstIP(ips string) string {
	parts := strings.Split(ips, ",")
	for i, part := range parts {
		ip := strings.TrimSpace(part)
		if ip != "" && net.ParseIP(ip) != nil {
			_ = i // return first valid IP
			return ip
		}
	}
	// Fallback: try first element
	if len(parts) > 0 {
		ip := strings.TrimSpace(parts[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return time.Now().UTC().Format("20060102150405") + "-" + randomString(8)
}

// randomString generates a random string
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[(time.Now().UnixNano()+int64(i))%int64(len(letters))]
	}
	return string(b)
}
