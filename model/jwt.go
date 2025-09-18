package model

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JwtPayload JWT payload
type JwtPayload struct {
	UserID      string     `json:"userId"`
	Roles       []string   `json:"roles"`
	Permissions [][]string `json:"permissions"`

	Iat int64 `json:"iat"`
	Exp int64 `json:"exp,omitempty"`
}

// Implements jwt.Claims interface
func (s JwtPayload) GetAudience() (jwt.ClaimStrings, error) {
	return nil, nil
}

func (s JwtPayload) GetExpirationTime() (*jwt.NumericDate, error) {
	if s.Exp == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(s.Exp, 0)), nil
}

func (s JwtPayload) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(s.Iat, 0)), nil
}

func (s JwtPayload) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

func (s JwtPayload) GetIssuer() (string, error) {
	return "", nil
}

func (s JwtPayload) GetSubject() (string, error) {
	return "", nil
}

type JwtVerifyRequest struct {
	Token string `json:"token"`
}

type JwtVerifyResponse struct {
	Valid   bool           `json:"valid"`
	Payload map[string]any `json:"payload,omitempty"`
}

type JwtRefreshRequest struct {
	Token string `json:"token"`
}

type JwtRefreshResponse struct {
	Token string `json:"token"`
}

type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}
