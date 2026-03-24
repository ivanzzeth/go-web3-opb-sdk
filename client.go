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
	httpClient    *http.Client

	mu             sync.Mutex
	cachedJwtToken string
	cachedJwks     *model.JWKSResponse
	cachedJwksTime *time.Time
}

// Option configures the Client during construction.
type Option func(*Client) error

// WithAuth registers the auth service URL and sets the signing key.
// This is required for any operation that needs authentication.
func WithAuth(baseURL, privateKeyHex string) Option {
	return func(c *Client) error {
		if baseURL == "" {
			return fmt.Errorf("auth baseURL is required")
		}
		if _, err := url.Parse(baseURL); err != nil {
			return fmt.Errorf("auth baseURL is invalid: %w", err)
		}
		if privateKeyHex == "" {
			return fmt.Errorf("privateKeyHex is required")
		}
		pk, err := crypto.HexToECDSA(privateKeyHex)
		if err != nil {
			return fmt.Errorf("privateKeyHex is invalid: %w", err)
		}
		c.services[ServiceAuth] = baseURL
		c.ethPrivateKey = pk
		c.ethAddress = crypto.PubkeyToAddress(pk.PublicKey)
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
//	client, err := web3opb.NewClient(
//	    web3opb.WithAuth("https://auth.web3gate.xyz", privateKeyHex),
//	    web3opb.WithDomain("evm-filter.web3gate.xyz"),
//	    web3opb.WithService("notification", "https://notify.web3gate.xyz"),
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
