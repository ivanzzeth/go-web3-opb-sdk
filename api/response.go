package api

import (
	"math/rand"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ivanzzeth/go-web3-opb-sdk/model"
)

var rng *rand.Rand

func init() {
	// Initialize random number generator
	rng = rand.New(rand.NewSource(time.Now().UnixNano()))
}

// SuccessResponse success response
func SuccessResponse[T any](c *gin.Context, data T) {
	c.JSON(http.StatusOK, model.ApiResponse[T]{
		Data:      data,
		Timestamp: time.Now().Unix(),
		RequestID: getRequestID(c),
	})
}

// ErrorResponse error response
func ErrorResponse(c *gin.Context, err error) {
	apiErr, ok := err.(model.ApiError)
	if !ok {
		apiErr = model.ApiError{
			Code: model.ErrCodeInternalServerError,
			Msg:  err.Error(),
		}
	}
	c.JSON(http.StatusOK, model.ApiResponse[any]{
		ApiError:  apiErr,
		Timestamp: time.Now().Unix(),
		RequestID: getRequestID(c),
	})
}

// getRequestID get request ID
func getRequestID(c *gin.Context) string {
	if requestID, exists := c.Get("requestId"); exists {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}

// GenerateRequestID generate request ID
func GenerateRequestID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

// randomString generate random string
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rng.Intn(len(charset))]
	}
	return string(b)
}
