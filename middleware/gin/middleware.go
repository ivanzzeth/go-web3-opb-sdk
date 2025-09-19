package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"context"

	"github.com/gin-gonic/gin"
	web3opb "github.com/ivanzzeth/go-web3-opb-sdk"
	"github.com/ivanzzeth/go-web3-opb-sdk/api"
	"github.com/ivanzzeth/go-web3-opb-sdk/model"
	"golang.org/x/time/rate"
)

func JwtMiddleware(client *web3opb.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString != "" {
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")
			result, err := client.JwtVerifyLocally(&model.JwtVerifyRequest{Token: tokenString})
			if err != nil {
				api.ErrorResponse(c, err)
				c.Abort()
				return
			}
			if !result.Valid {
				api.ErrorResponse(c, fmt.Errorf("unauthorized"))
				c.Abort()
				return
			}

			c.Set("userId", result.Payload["userId"])
			c.Next()
			return
		}

		c.Next()
	}
}

// AuthMiddleware authentication middleware
func AuthMiddleware(client *web3opb.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			api.ErrorResponse(c, fmt.Errorf("unauthorized"))
			c.Abort()
			return
		}
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		result, err := client.JwtVerifyLocally(&model.JwtVerifyRequest{Token: tokenString})
		if err != nil {
			api.ErrorResponse(c, err)
			c.Abort()
			return
		}

		if !result.Valid {
			api.ErrorResponse(c, fmt.Errorf("unauthorized"))
			c.Abort()
			return
		}

		// fmt.Printf(">>>>ACCESS1: %v\n", result.Payload)

		// Check if user has permission to access the resource
		// Use FullPath() to get the route pattern (e.g., /users/:id instead of /users/123)
		path := c.FullPath()
		method := c.Request.Method
		payloadJson, err := json.Marshal(result.Payload)
		if err != nil {
			api.ErrorResponse(c, err)
			c.Abort()
			return
		}
		jwtPayload := model.JwtPayload{}
		err = json.Unmarshal(payloadJson, &jwtPayload)
		if err != nil {
			api.ErrorResponse(c, err)
			c.Abort()
			return
		}
		// fmt.Printf(">>>>ACCESS2: %v\n", jwtPayload)
		// userIdStr is already a string in JwtPayload

		permissions := jwtPayload.Permissions

		// log.Info("Check Access", "userId", jwtPayload.UserID, "path", path, "method", method, "permissions", permissions)
		// fmt.Printf(">>>>ACCESS3: %v %v %v: %v\n", jwtPayload.UserID, path, method, permissions)

		for _, permission := range permissions {
			if len(permission) != 3 {
				api.ErrorResponse(c, fmt.Errorf("invalid permissions length"))
				c.Abort()
				return
			}
			if permission[1] == path && permission[2] == method {
				// Convert string userId to uint64 for context
				// userId, err := strconv.ParseUint(jwtPayload.UserID, 10, 64)
				// if err != nil {
				// 	api.ErrorResponse(c, fmt.Errorf("invalid userId format"))
				// 	c.Abort()
				// 	return
				// }
				// c.Set("userId", userId)

				c.Next()
				return
			}
		}

		api.ErrorResponse(c, fmt.Errorf("unauthorized"))
		c.Abort()
	}
}

// LoggerMiddleware logging middleware
func LoggerMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] user\"[%v] %s %s %s statusCode=%d latency=%s agent=%s err=%s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Keys["userId"],
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}

// RecoveryMiddleware recovery middleware
func RecoveryMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		var err error
		if errStr, ok := recovered.(string); ok {
			err = fmt.Errorf("panic: %s", errStr)
		} else if panicErr, ok := recovered.(error); ok {
			err = fmt.Errorf("panic: %w", panicErr)
		} else {
			err = fmt.Errorf("panic: %v", recovered)
		}
		api.ErrorResponse(c, err)
		c.Abort()
	})
}

// RateLimitMiddleware rate limiting middleware
func RateLimitMiddleware(limit int) gin.HandlerFunc {
	limiter := rate.NewLimiter(rate.Limit(limit), limit)
	return func(c *gin.Context) {
		if !limiter.Allow() {
			api.ErrorResponse(c, fmt.Errorf("rate limit exceeded"))
			c.Abort()
			return
		}
		c.Next()
	}
}

// TimeoutMiddleware timeout middleware
func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)

		done := make(chan bool, 1)
		go func() {
			c.Next()
			done <- true
		}()

		select {
		case <-done:
			return
		case <-ctx.Done():
			api.ErrorResponse(c, fmt.Errorf("request timeout"))
			c.Abort()
			return
		}
	}
}

// MetricsMiddleware metrics middleware
func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		// Record request metrics
		duration := time.Since(start)
		status := c.Writer.Status()

		// TODO: send metrics to monitoring system
		_ = duration
		_ = status
	}
}

// CORSMiddleware CORS middleware
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, PATCH")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-Request-ID")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length, X-Request-ID")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// RequestIDMiddleware request ID middleware
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = api.GenerateRequestID()
		}
		c.Set("requestId", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}
