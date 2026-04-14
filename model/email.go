package model

// EmailRegisterRequest register with email + password
type EmailRegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

// EmailLoginRequest login with email + password
type EmailLoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// EmailResendVerificationRequest resend verification email
type EmailResendVerificationRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// EmailLoginResult login result
type EmailLoginResult struct {
	User struct {
		UserID uint64 `json:"userId"`
		Email  string `json:"email"`
	} `json:"user"`
	Token string `json:"token"`
}
