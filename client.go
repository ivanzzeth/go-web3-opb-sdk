package web3opb

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ivanzzeth/go-web3-opb-sdk/model"
)

// Well-known service names.
const (
	ServiceAuth = "auth" // Authentication service (SIWE, JWT, users, projects, RBAC)
)

// Client is the SDK entry point for interacting with web3-opb services.
type Client struct {
	services      map[string]string // service name → base URL
	domain        string
	version       string
	ethPrivateKey *ecdsa.PrivateKey
	ethAddress    common.Address
	clientID      string // OAuth2 client_id for service-to-service auth
	clientSecret  string // OAuth2 client_secret for service-to-service auth
	httpClient    *http.Client

	mu             sync.Mutex
	cachedJwtToken string
	cachedJwks     *model.JWKSResponse
	cachedJwksTime *time.Time
}

// Option configures the Client during construction.
type Option func(*Client) error

// WithAuth registers the auth service URL and sets the SIWE signing key.
// Deprecated: Use WithAuthService + WithSIWE or WithClientCredentials instead.
func WithAuth(baseURL, privateKeyHex string) Option {
	return func(c *Client) error {
		if err := WithAuthService(baseURL)(c); err != nil {
			return err
		}
		return WithSIWE(privateKeyHex)(c)
	}
}

// WithAuthService registers the auth service base URL.
// Use this when you only need to verify JWTs or call public auth endpoints.
// No credentials required — suitable for downstream services that validate user tokens.
//
//	client, _ := web3opb.NewClient(
//	    web3opb.WithAuthService("http://auth:8700"),
//	)
//	client.JwtVerify(token) // works without any credentials
func WithAuthService(baseURL string) Option {
	return func(c *Client) error {
		if baseURL == "" {
			return fmt.Errorf("auth baseURL is required")
		}
		if _, err := url.Parse(baseURL); err != nil {
			return fmt.Errorf("auth baseURL is invalid: %w", err)
		}
		c.services[ServiceAuth] = baseURL
		return nil
	}
}

// WithSIWE sets the ETH private key for SIWE (Sign-In with Ethereum) authentication.
// Use this for user-facing clients that need to sign SIWE messages.
func WithSIWE(privateKeyHex string) Option {
	return func(c *Client) error {
		if privateKeyHex == "" {
			return fmt.Errorf("privateKeyHex is required")
		}
		pk, err := crypto.HexToECDSA(privateKeyHex)
		if err != nil {
			return fmt.Errorf("privateKeyHex is invalid: %w", err)
		}
		c.ethPrivateKey = pk
		c.ethAddress = crypto.PubkeyToAddress(pk.PublicKey)
		return nil
	}
}

// WithClientCredentials sets OAuth2 client_id and client_secret for service-to-service auth.
// Use this for backend services that authenticate via project-scoped credentials (ADR-006).
//
//	client, _ := web3opb.NewClient(
//	    web3opb.WithAuthService("http://auth:8700"),
//	    web3opb.WithClientCredentials("w3opb_pk_xxx", "w3opb_sk_xxx"),
//	)
func WithClientCredentials(clientID, clientSecret string) Option {
	return func(c *Client) error {
		if clientID == "" {
			return fmt.Errorf("clientID is required")
		}
		if clientSecret == "" {
			return fmt.Errorf("clientSecret is required")
		}
		c.clientID = clientID
		c.clientSecret = clientSecret
		return nil
	}
}

// WithService registers an additional microservice by name and base URL.
//
//	client.Service("notification").Post(...)
func WithService(name, baseURL string) Option {
	return func(c *Client) error {
		if name == "" {
			return fmt.Errorf("service name is required")
		}
		if baseURL == "" {
			return fmt.Errorf("service baseURL is required for %q", name)
		}
		if _, err := url.Parse(baseURL); err != nil {
			return fmt.Errorf("service baseURL is invalid for %q: %w", name, err)
		}
		c.services[name] = baseURL
		return nil
	}
}

// WithDomain sets the SIWE domain (e.g. "evm-filter.web3gate.xyz").
func WithDomain(domain string) Option {
	return func(c *Client) error {
		if domain == "" {
			return fmt.Errorf("domain is required")
		}
		c.domain = domain
		return nil
	}
}

// WithVersion sets the API version prefix (default "v1").
func WithVersion(version string) Option {
	return func(c *Client) error {
		if !strings.HasPrefix(version, "v") {
			return fmt.Errorf("version must start with 'v'")
		}
		c.version = version
		return nil
	}
}

// WithHTTPClient overrides the default http.Client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) error {
		c.httpClient = hc
		return nil
	}
}

// NewClient creates a Client configured via functional options.
//
// Service-to-service (verify user JWTs, no signing):
//
//	client, err := web3opb.NewClient(
//	    web3opb.WithAuthService("http://auth:8700"),
//	)
//
// Service-to-service with client credentials (ADR-006):
//
//	client, err := web3opb.NewClient(
//	    web3opb.WithAuthService("http://auth:8700"),
//	    web3opb.WithClientCredentials("w3opb_pk_xxx", "w3opb_sk_xxx"),
//	)
//
// User-facing client (SIWE login):
//
//	client, err := web3opb.NewClient(
//	    web3opb.WithAuthService("http://auth:8700"),
//	    web3opb.WithSIWE(privateKeyHex),
//	    web3opb.WithDomain("app.example.com"),
//	)
func NewClient(opts ...Option) (*Client, error) {
	c := &Client{
		services:   make(map[string]string),
		version:    "v1",
		httpClient: &http.Client{},
	}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// ServiceURL returns the base URL for the named service.
// Panics if the service is not registered — callers should validate at construction time.
func (c *Client) ServiceURL(name string) string {
	u, ok := c.services[name]
	if !ok {
		panic(fmt.Sprintf("web3opb: service %q not registered", name))
	}
	return u
}

// authBaseURL is a convenience accessor used internally.
func (c *Client) authBaseURL() string {
	return c.ServiceURL(ServiceAuth)
}

// ClientID returns the OAuth2 client_id, or empty if not configured.
func (c *Client) ClientID() string {
	return c.clientID
}

// ClientSecret returns the OAuth2 client_secret, or empty if not configured.
func (c *Client) ClientSecret() string {
	return c.clientSecret
}
