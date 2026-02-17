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
func RateLimitMiddleware(requestsPerSecond int, burst int) gin.HandlerFunc {
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
func RealIPMiddleware(trustedProxies []string) gin.HandlerFunc {
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

		// Check if the remote address is a trusted proxy
		isTrusted := false
		for _, ipNet := range trustedNets {
			if ipNet.Contains(remoteIP) {
				isTrusted = true
				break
			}
		}

		if !isTrusted && len(trustedNets) > 0 {
			// Not from a trusted proxy, don't trust headers
			c.Next()
			return
		}

		// Try to get real IP from headers (in order of preference)
		realIP := extractRealIP(c)
		if realIP != "" {
			// Store the original remote address
			c.Set("original_remote_addr", c.ClientIP())
			// Update the request's RemoteAddr
			c.Request.RemoteAddr = realIP
		}

		c.Next()
	}
}

// extractRealIP extracts the real client IP from proxy headers
func extractRealIP(c *gin.Context) string {
	// Try X-Forwarded-For first (most common)
	xff := c.GetHeader("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For may contain multiple IPs: client, proxy1, proxy2, ...
		// The first non-trusted IP is the real client
		ips := strings.Split(xff, ",")
		for i, ip := range ips {
			ip = strings.TrimSpace(ip)
			if ip != "" && net.ParseIP(ip) != nil {
				// Return the first IP (leftmost = original client)
				if i == 0 {
					return ip
				}
			}
		}
		// If all IPs are valid, return the first one
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Try X-Real-IP
	xri := c.GetHeader("X-Real-IP")
	if xri != "" {
		ip := strings.TrimSpace(xri)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	// Try X-Client-IP
	xci := c.GetHeader("X-Client-IP")
	if xci != "" {
		ip := strings.TrimSpace(xci)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	// Try True-Client-IP (used by some CDNs like Cloudflare)
	tci := c.GetHeader("True-Client-IP")
	if tci != "" {
		ip := strings.TrimSpace(tci)
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
