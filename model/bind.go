package model

// AuthType authentication type
type AuthType string

const (
	AuthTypeSIWE   AuthType = "siwe"
	AuthTypeOAuth2 AuthType = "oauth2"
	AuthTypeEmail  AuthType = "email"
)

// BindAuthRequest bind another auth method to current user
type BindAuthRequest struct {
	AuthType AuthType `json:"authType" binding:"required"`

	// For SIWE binding: fresh SIWE message and signature
	SiweMessage   string `json:"siweMessage,omitempty"`
	SiweSignature string `json:"siweSignature,omitempty"`

	// For OAuth2 binding: fresh auth code (from POST /oauth2/token flow)
	AuthCode string `json:"authCode,omitempty"`

	// For Email binding: email + password
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}
