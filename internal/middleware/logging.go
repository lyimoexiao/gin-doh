package middleware

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lyimoexiao/gin-doh/internal/logger"
)

// LoggingMiddleware 日志中间件
func LoggingMiddleware(log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		// 处理请求
		c.Next()

		// 记录访问日志
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

// RecoveryMiddleware 恢复中间件
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

// CORSMiddleware CORS 中间件
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

// RateLimitMiddleware 速率限制中间件
func RateLimitMiddleware(requestsPerSecond int, burst int) gin.HandlerFunc {
	// 简化实现，实际应该使用 golang.org/x/time/rate
	return func(c *gin.Context) {
		c.Next()
	}
}

// RequestIDMiddleware 请求 ID 中间件
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

// generateRequestID 生成请求 ID
func generateRequestID() string {
	return time.Now().UTC().Format("20060102150405") + "-" + randomString(8)
}

// randomString 生成随机字符串
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[(time.Now().UnixNano()+int64(i))%int64(len(letters))]
	}
	return string(b)
}
