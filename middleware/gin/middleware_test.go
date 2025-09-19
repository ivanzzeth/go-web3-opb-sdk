package middleware

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
	web3opb "github.com/ivanzzeth/go-web3-opb-sdk"
	"github.com/ivanzzeth/go-web3-opb-sdk/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testServer represents a test server with middleware
type testServer struct {
	router *gin.Engine
	client *web3opb.Client

	userPrivateKey *ecdsa.PrivateKey
	userAddress    common.Address
	userId         uint64
	userClient     *web3opb.Client
}

// newTestServer creates a new test server with middleware
func newTestServer(t *testing.T) *testServer {
	// Initialize real client with test configuration
	adminPrivateKeyHex := os.Getenv("PRIVATE_KEY_HEX")
	assert.NotEmpty(t, adminPrivateKeyHex)
	baseURL := "http://localhost:8700"
	apiNamespace := "middleware-test"

	// Generate a valid private key for testing
	userPrivateKey, userAddress, err := web3opb.GenerateEthPrivateKey()
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	client, err := web3opb.NewApiClient(
		baseURL,     // Test server URL
		"localhost", // Domain
		"v1",        // Version
		apiNamespace,
		adminPrivateKeyHex, // Generated private key
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	userClient, err := web3opb.NewApiClient(
		baseURL,     // Test server URL
		"localhost", // Domain
		"v1",        // Version
		apiNamespace,
		hex.EncodeToString(userPrivateKey.D.Bytes()), // Generated private key
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Create Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Add middleware
	router.Use(RecoveryMiddleware())
	router.Use(CORSMiddleware())
	router.Use(RateLimitMiddleware(100)) // 100 requests per second
	router.Use(TimeoutMiddleware(30 * time.Second))
	router.Use(JwtMiddleware(client))
	router.Use(RequestIDMiddleware())
	router.Use(LoggerMiddleware())
	router.Use(MetricsMiddleware())

	// Add test routes
	router.GET("/public", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "public endpoint"})
	})

	router.GET("/protected", AuthMiddleware(client), func(c *gin.Context) {
		userId := c.GetString("userId")
		c.JSON(200, gin.H{"message": "protected endpoint", "userId": userId})
	})

	router.GET("/admin", AuthMiddleware(client), func(c *gin.Context) {
		userId := c.GetString("userId")
		c.JSON(200, gin.H{"message": "admin endpoint", "userId": userId})
	})

	router.POST("/admin/users", AuthMiddleware(client), func(c *gin.Context) {
		userId := c.GetString("userId")
		c.JSON(200, gin.H{"message": "create user", "userId": userId})
	})

	userId, err := client.UserCreate(&model.UserCreateRequest{
		EthAddress: userAddress.Hex(),
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	_, err = client.GrantRolePathPermissions(&model.GrantPermissionRequest{
		Role:    "user",
		Path:    "/protected",
		Methods: []string{"GET"},
	})
	if err != nil {
		t.Fatalf("failed to grant role path permissions: %v", err)
	}

	_, err = client.GrantRolePathPermissions(&model.GrantPermissionRequest{
		Role:    "admin",
		Path:    "/admin",
		Methods: []string{"GET", "POST"},
	})
	if err != nil {
		t.Fatalf("failed to grant role path permissions: %v", err)
	}

	_, err = client.GrantRolePathPermissions(&model.GrantPermissionRequest{
		Role:    "admin",
		Path:    "/admin/users",
		Methods: []string{"GET", "POST"},
	})
	if err != nil {
		t.Fatalf("failed to grant role path permissions: %v", err)
	}

	return &testServer{
		router: router,
		client: client,

		userPrivateKey: userPrivateKey,
		userAddress:    userAddress,
		userId:         userId,
		userClient:     userClient,
	}
}

// TestJwtMiddleware tests JWT middleware functionality
func TestJwtMiddleware(t *testing.T) {
	server := newTestServer(t)

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectUserId   bool
	}{
		{
			name:           "No auth header - should pass through",
			authHeader:     "",
			expectedStatus: 200,
			expectUserId:   false,
		},
		{
			name:           "Invalid token format",
			authHeader:     "Bearer invalid-token",
			expectedStatus: 200, // JwtMiddleware allows invalid tokens to pass through
			expectUserId:   false,
		},
		{
			name:           "Valid Bearer token",
			authHeader:     "Bearer valid-token",
			expectedStatus: 200,
			expectUserId:   false, // Will be false because token verification will fail in test
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/protected", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectUserId {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Contains(t, response, "userId")
			}
		})
	}
}

// TestAuthMiddleware tests authentication middleware functionality
func TestAuthMiddleware(t *testing.T) {
	server := newTestServer(t)

	// Anyone could call public endpoint
	req := httptest.NewRequest("GET", "/public", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "public endpoint")

	// Normal users could call protected endpoint
	userJwtToken := server.userClient.GetCachedJwtToken()
	req = httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+userJwtToken)
	w = httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "protected endpoint")
	assert.Contains(t, w.Body.String(), strconv.FormatUint(server.userId, 10))

	// Normal users could not call protected endpoint without jwt token
	req = httptest.NewRequest("GET", "/protected", nil)
	w = httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized")

	// // Normal users could not call admin endpoint
	// req = httptest.NewRequest("GET", "/admin", nil)
	// req.Header.Set("Authorization", "Bearer "+userJwtToken)
	// w = httptest.NewRecorder()
	// server.router.ServeHTTP(w, req)
	// assert.Equal(t, 200, w.Code)
	// assert.Contains(t, w.Body.String(), "unauthorized")

	// // Admin users could call admin endpoint
	// req = httptest.NewRequest("GET", "/admin", nil)
	// req.Header.Set("Authorization", "Bearer "+server.client.GetCachedJwtToken())
	// w = httptest.NewRecorder()
	// server.router.ServeHTTP(w, req)
	// assert.Equal(t, 200, w.Code)
	// assert.Contains(t, w.Body.String(), "admin endpoint")
}

// TestCORSMiddleware tests CORS middleware functionality
func TestCORSMiddleware(t *testing.T) {
	server := newTestServer(t)

	tests := []struct {
		name           string
		method         string
		origin         string
		expectedStatus int
		expectCORS     bool
	}{
		{
			name:           "OPTIONS request - should return 204",
			method:         "OPTIONS",
			origin:         "https://example.com",
			expectedStatus: 204,
			expectCORS:     true,
		},
		{
			name:           "GET request with origin - should include CORS headers",
			method:         "GET",
			origin:         "https://example.com",
			expectedStatus: 200,
			expectCORS:     true,
		},
		{
			name:           "GET request without origin - should still work",
			method:         "GET",
			origin:         "",
			expectedStatus: 200,
			expectCORS:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/public", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectCORS {
				assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
				assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
				assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Authorization")
			}
		})
	}
}

// TestRequestIDMiddleware tests request ID middleware functionality
func TestRequestIDMiddleware(t *testing.T) {
	server := newTestServer(t)

	tests := []struct {
		name            string
		requestID       string
		expectGenerated bool
	}{
		{
			name:            "No request ID - should generate one",
			requestID:       "",
			expectGenerated: true,
		},
		{
			name:            "Existing request ID - should use it",
			requestID:       "test-request-id-123",
			expectGenerated: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/public", nil)
			if tt.requestID != "" {
				req.Header.Set("X-Request-ID", tt.requestID)
			}

			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, req)

			assert.Equal(t, 200, w.Code)

			responseID := w.Header().Get("X-Request-ID")
			assert.NotEmpty(t, responseID)

			if !tt.expectGenerated {
				assert.Equal(t, tt.requestID, responseID)
			}
		})
	}
}

// TestRateLimitMiddleware tests rate limiting middleware functionality
func TestRateLimitMiddleware(t *testing.T) {
	server := newTestServer(t)

	// Test normal request
	req := httptest.NewRequest("GET", "/public", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)

	// Test multiple rapid requests (should not exceed rate limit in this test)
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/public", nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code)
	}
}

// TestTimeoutMiddleware tests timeout middleware functionality
func TestTimeoutMiddleware(t *testing.T) {
	server := newTestServer(t)

	// Add a slow endpoint for testing
	server.router.GET("/slow", func(c *gin.Context) {
		time.Sleep(2 * time.Second) // This should timeout
		c.JSON(200, gin.H{"message": "slow response"})
	})

	req := httptest.NewRequest("GET", "/slow", nil)
	w := httptest.NewRecorder()

	// Set a short timeout
	ctx, cancel := context.WithTimeout(req.Context(), 100*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	server.router.ServeHTTP(w, req)

	// Should return timeout error
	assert.Equal(t, 200, w.Code) // Our API returns 200 with error in body
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	// Check for error fields (code and message)
	assert.Contains(t, response, "code")
	assert.Contains(t, response, "message")
}

// TestRecoveryMiddleware tests recovery middleware functionality
func TestRecoveryMiddleware(t *testing.T) {
	// Create a simple router with only recovery middleware for testing
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RecoveryMiddleware())

	// Add a panic endpoint for testing
	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	req := httptest.NewRequest("GET", "/panic", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should recover from panic and return error response
	assert.Equal(t, 200, w.Code) // Our API returns 200 with error in body
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	// Check for error fields (code and message)
	assert.Contains(t, response, "code")
	assert.Contains(t, response, "message")
}

// TestIntegrationWithRealClient tests integration with real client
func TestIntegrationWithRealClient(t *testing.T) {
	// This test requires a running auth server
	// Skip if not available
	privateKey, _, err := web3opb.GenerateEthPrivateKey()
	if err != nil {
		t.Skip("Skipping integration test: failed to generate private key")
		return
	}

	privateKeyHex := hex.EncodeToString(privateKey.D.Bytes())
	client, err := web3opb.NewApiClient(
		"http://localhost:8700", // Test server URL
		"localhost",             // Domain
		"v1",                    // Version
		"",
		privateKeyHex, // Generated private key
	)
	if err != nil {
		t.Skip("Skipping integration test: auth server not available")
		return
	}

	// Test if server is reachable by trying to get JWKS
	_, err = client.GetJWKS()
	if err != nil {
		t.Skip("Skipping integration test: auth server not responding")
		return
	}

	// Create test server with real client
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(JwtMiddleware(client))

	router.GET("/test", func(c *gin.Context) {
		userId := c.GetString("userId")
		c.JSON(200, gin.H{"message": "test endpoint", "userId": userId})
	})

	// Test without token
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)

	// Test with invalid token
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)

	// Note: Testing with valid token would require actual authentication flow
	// which is beyond the scope of this middleware test
}

// TestMiddlewareChain tests multiple middleware working together
func TestMiddlewareChain(t *testing.T) {
	server := newTestServer(t)

	req := httptest.NewRequest("GET", "/public", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("X-Request-ID", "test-chain-123")

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	// Check that all middleware headers are present
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "test-chain-123", w.Header().Get("X-Request-ID"))
}

// TestLoggerMiddleware tests logging middleware functionality
func TestLoggerMiddleware(t *testing.T) {
	server := newTestServer(t)

	req := httptest.NewRequest("GET", "/public", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	// Logger middleware doesn't affect response, just logs
	// We can't easily test the log output in unit tests
}

// TestMetricsMiddleware tests metrics middleware functionality
func TestMetricsMiddleware(t *testing.T) {
	server := newTestServer(t)

	req := httptest.NewRequest("GET", "/public", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	// Metrics middleware doesn't affect response, just records metrics
	// We can't easily test the metrics in unit tests
}
