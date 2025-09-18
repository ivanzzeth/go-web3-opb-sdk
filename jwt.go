package web3opb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ivanzzeth/go-web3-opb-sdk/model"
	"github.com/lestrrat-go/backoff/v2"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spruceid/siwe-go"
)

func (c *ApiClient) JwtVerify(token *model.JwtVerifyRequest) (*model.JwtVerifyResponse, error) {
	url := fmt.Sprintf("%s/api/%s/jwt/verify", c.baseURL, c.version)
	tokenJson, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(url, "application/json", bytes.NewBuffer(tokenJson))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jwtVerifyResultResp model.APIResponse[model.JwtVerifyResponse]
	err = json.NewDecoder(resp.Body).Decode(&jwtVerifyResultResp)
	if err != nil {
		return nil, err
	}

	if jwtVerifyResultResp.ApiError.HasError() {
		return nil, jwtVerifyResultResp.ApiError
	}

	return &jwtVerifyResultResp.Data, nil
}

func (c *ApiClient) GetJWKS() (*model.JWKSResponse, error) {
	var jwksResp model.JWKSResponse

	if c.cachedJwksTime == nil || time.Since(*c.cachedJwksTime) > 10*time.Minute {
		url := fmt.Sprintf("%s/.well-known/jwks.json", c.baseURL)

		resp, err := c.httpClient.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		err = json.NewDecoder(resp.Body).Decode(&jwksResp)
		if err != nil {
			return nil, err
		}

		now := time.Now()

		c.mu.Lock()
		c.cachedJwks = &jwksResp
		c.cachedJwksTime = &now
		c.mu.Unlock()
	} else {
		jwksResp = *c.cachedJwks
	}

	return &jwksResp, nil
}

func (c *ApiClient) JwtVerifyLocally(token *model.JwtVerifyRequest) (*model.JwtVerifyResponse, error) {
	// jwksResp, err := c.GetJWKS()
	// if err != nil {
	// 	return nil, err
	// }

	url := fmt.Sprintf("%s/.well-known/jwks.json", c.baseURL)

	jwtToken, err := verifyJWT(context.Background(), c.httpClient, token.Token, url)
	if err != nil {
		return nil, err
	}

	return &model.JwtVerifyResponse{
		Valid:   jwtToken.Valid,
		Payload: jwtToken.Claims.(jwt.MapClaims),
	}, nil
}

func (c *ApiClient) JwtRefresh(token *model.JwtRefreshRequest) (*model.JwtRefreshResponse, error) {
	url := fmt.Sprintf("%s/api/%s/jwt/refresh", c.baseURL, c.version)
	tokenJson, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(url, "application/json", bytes.NewBuffer(tokenJson))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jwtRefreshResultResp model.APIResponse[model.JwtRefreshResponse]
	err = json.NewDecoder(resp.Body).Decode(&jwtRefreshResultResp)
	if err != nil {
		return nil, err
	}

	if jwtRefreshResultResp.ApiError.HasError() {
		return nil, jwtRefreshResultResp.ApiError
	}

	return &jwtRefreshResultResp.Data, nil
}

func (c *ApiClient) GetCachedJwtToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	valid, err := c.JwtVerifyLocally(&model.JwtVerifyRequest{Token: c.cachedJwtToken})
	if err != nil || !valid.Valid {
		// Refresh token first
		newTokenResp, err := c.JwtRefresh(&model.JwtRefreshRequest{Token: c.cachedJwtToken})
		if err == nil && newTokenResp.Token != c.cachedJwtToken {
			c.cachedJwtToken = newTokenResp.Token
		} else {
			// If same token, sign in again
			if c.ethPrivateKey != nil {
				// Use SIWE to sign in again
				nonce, err := c.SiweGetNonce()
				if err != nil {
					return ""
				}
				// TODO: Configurable
				message, err := siwe.InitMessage(c.domain, c.ethAddress.Hex(), c.baseURL, nonce, map[string]interface{}{
					"issuedAt":       time.Now().UTC().Format(time.RFC3339),
					"expirationTime": time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
				})
				if err != nil {
					return ""
				}
				messageModel, err := c.SiweSignMessage(message)
				if err != nil {
					return ""
				}
				siweAuthResult, err := c.SiweVerify(messageModel)
				if err != nil {
					return ""
				}
				c.cachedJwtToken = siweAuthResult.Token
			}
		}
	}
	return c.cachedJwtToken
}

func verifyJWT(ctx context.Context, httpClient *http.Client, tokenString, jwksURL string) (*jwt.Token, error) {
	// TODO: Optimize
	set, err := jwk.Fetch(ctx, jwksURL,
		jwk.WithHTTPClient(httpClient),
		jwk.WithFetchBackoff(backoff.Exponential(backoff.WithMaxInterval(10*time.Second), backoff.WithMaxRetries(3))),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not found in token header")
		}

		key, found := set.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("key not found: %s", kid)
		}

		var rawkey interface{}
		if err := key.Raw(&rawkey); err != nil {
			return nil, fmt.Errorf("failed to get raw key: %v", err)
		}

		return rawkey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	return token, nil
}
