package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApiError(t *testing.T) {
	apiErr := ApiError{
		Code: 400,
		Msg:  "bad request",
	}

	assert.Equal(t, int(400), apiErr.Code)
	assert.Equal(t, "bad request", apiErr.Msg)
}

func TestNewErrInvalidRequest(t *testing.T) {
	// Test with nil error
	err1 := NewErrInvalidRequest(nil)
	assert.Equal(t, (ErrCodeInvalidRequest), err1.Code)
	assert.Equal(t, "invalid request", err1.Msg)

	// Test with error
	testErr := assert.AnError
	err2 := NewErrInvalidRequest(testErr)
	assert.Equal(t, (ErrCodeInvalidRequest), err2.Code)
	assert.Equal(t, testErr.Error(), err2.Msg)
}

func TestNewErrInternalServerError(t *testing.T) {
	// Test with nil error
	err1 := NewErrInternalServerError(nil)
	assert.Equal(t, ErrCodeInternalServerError, err1.Code)
	assert.Equal(t, "internal server error", err1.Msg)

	// Test with error
	testErr := assert.AnError
	err2 := NewErrInternalServerError(testErr)
	assert.Equal(t, ErrCodeInternalServerError, err2.Code)
	assert.Equal(t, testErr.Error(), err2.Msg)
}

func TestComposeID(t *testing.T) {
	// Test basic composition
	id1 := ComposeID("key1", "key2", "key3")
	assert.True(t, len(id1) > 0)
	assert.True(t, id1[:2] == "0x")

	// Test consistency
	id2 := ComposeID("key1", "key2", "key3")
	assert.Equal(t, id1, id2)

	// Test different keys produce different IDs
	id3 := ComposeID("key1", "key2", "key4")
	assert.NotEqual(t, id1, id3)

	// Test single key
	id4 := ComposeID("single")
	assert.True(t, len(id4) > 0)
	assert.True(t, id4[:2] == "0x")
}
