package model

// APIResponse unified API response structure
type APIResponse[T any] struct {
	ApiError

	Data      T      `json:"data,omitempty"`
	Timestamp int64  `json:"timestamp"`
	RequestID string `json:"requestId,omitempty"`
}
