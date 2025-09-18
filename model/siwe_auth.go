package model

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SiweErrorCode defines SIWE error codes
type SiweErrorCode int

const (
	// Success
	SiweErrorCodeSuccess SiweErrorCode = 0

	// Validation errors (1000-1999)
	SiweErrorCodeValidationError           SiweErrorCode = 1000
	SiweErrorCodeMissingMessageOrSignature SiweErrorCode = 1001
	SiweErrorCodeInvalidSIWEMessage        SiweErrorCode = 1002
	SiweErrorCodeMessageExpired            SiweErrorCode = 1003
	SiweErrorCodeMessageNotYetValid        SiweErrorCode = 1004
	SiweErrorCodeInvalidSignature          SiweErrorCode = 1005
	SiweErrorCodeMissingToken              SiweErrorCode = 1006
	SiweErrorCodeInvalidOrExpiredToken     SiweErrorCode = 1007

	// Business logic errors (2000-2999)
	SiweErrorCodeBusinessLogicError SiweErrorCode = 2000
	SiweErrorCodeUserAlreadyExists  SiweErrorCode = 2001
	SiweErrorCodeUserNotFound       SiweErrorCode = 2002

	// System errors (9000-9999)
	SiweErrorCodeServerError  SiweErrorCode = 9000
	SiweErrorCodeUnknownError SiweErrorCode = 9999
)

// SiweErrorMessages error message mapping
var SiweErrorMessages = map[SiweErrorCode]string{
	SiweErrorCodeSuccess:                   "Success",
	SiweErrorCodeValidationError:           "Validation error",
	SiweErrorCodeMissingMessageOrSignature: "Missing message or signature",
	SiweErrorCodeInvalidSIWEMessage:        "Invalid SIWE message",
	SiweErrorCodeMessageExpired:            "Message expired",
	SiweErrorCodeMessageNotYetValid:        "Message not yet valid",
	SiweErrorCodeInvalidSignature:          "Invalid signature",
	SiweErrorCodeMissingToken:              "Missing token",
	SiweErrorCodeInvalidOrExpiredToken:     "Invalid or expired token",
	SiweErrorCodeBusinessLogicError:        "Business logic error",
	SiweErrorCodeUserAlreadyExists:         "User already exists",
	SiweErrorCodeUserNotFound:              "User not found",
	SiweErrorCodeServerError:               "Server error",
	SiweErrorCodeUnknownError:              "Unknown error",
}

// SiweNonceResponse nonce request response
type SiweNonceResponse struct {
	Nonce string `json:"nonce"`
}

// SiweVerifyRequest SIWE message verification request
type SiweVerifyRequest struct {
	Message   string `json:"message" binding:"required"`
	Signature string `json:"signature" binding:"required"`
}

// SiweVerifyResponse authentication success response
type SiweVerifyResponse struct {
	User  SiweUser `json:"user"`
	Token string   `json:"token"`
}

// SiweUser user information
type SiweUser struct {
	UserID        uint64 `json:"userId"`
	WalletAddress string `json:"wallet_address"`
}

// SiweJwtPayload JWT payload
type SiweJwtPayload struct {
	JwtPayload
	EthAddress string `json:"ethAddress"`
	Domain     string `json:"domain"`
}

// Implements jwt.Claims interface
func (s SiweJwtPayload) GetAudience() (jwt.ClaimStrings, error) {
	return nil, nil
}

func (s SiweJwtPayload) GetExpirationTime() (*jwt.NumericDate, error) {
	if s.Exp == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(s.Exp, 0)), nil
}

func (s SiweJwtPayload) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(s.Iat, 0)), nil
}

func (s SiweJwtPayload) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

func (s SiweJwtPayload) GetIssuer() (string, error) {
	return "", nil
}

func (s SiweJwtPayload) GetSubject() (string, error) {
	return "", nil
}

// SiweAuth user authentication record
type SiweAuth struct {
	ID            uint      `json:"id" gorm:"primaryKey"`
	WalletAddress string    `json:"wallet_address" gorm:"uniqueIndex;not null"`
	Created       time.Time `json:"created"`
	LastLogin     time.Time `json:"last_login"`
}
