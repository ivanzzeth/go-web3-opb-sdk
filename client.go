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

type Client struct {
	ApiNamespace string // e.g. "notification", "wallet-services", etc.

	authBaseURL   string
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

func NewApiClient(authhBaseURL, domain, version, apiNamespace, ethPrivateKeyHex string) (*Client, error) {
	// Validate baseURL
	if authhBaseURL == "" {
		return nil, fmt.Errorf("baseURL is required")
	}

	_, err := url.Parse(authhBaseURL)
	if err != nil {
		return nil, fmt.Errorf("baseURL is invalid")
	}

	// Validate domain
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	// Validate version
	if version == "" {
		version = "v1"
	}

	if strings.HasPrefix(apiNamespace, "/") || strings.HasPrefix(apiNamespace, "v") {
		return nil, fmt.Errorf("apiNamespace must not start with '/' or 'v'")
	}

	if !strings.HasPrefix(version, "v") {
		return nil, fmt.Errorf("version must start with 'v'")
	}
	if version != "v1" {
		return nil, fmt.Errorf("version must be 'v1' for now")
	}

	if ethPrivateKeyHex == "" {
		return nil, fmt.Errorf("ethPrivateKeyHex is required")
	}

	ethPrivateKey, err := crypto.HexToECDSA(ethPrivateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("ethPrivateKeyHex is invalid")
	}

	ethAddress := crypto.PubkeyToAddress(ethPrivateKey.PublicKey)

	return &Client{
		authBaseURL:  authhBaseURL,
		domain:       domain,
		version:      version,
		ApiNamespace: apiNamespace,

		httpClient:    &http.Client{},
		ethPrivateKey: ethPrivateKey,
		ethAddress:    ethAddress,
	}, nil
}
