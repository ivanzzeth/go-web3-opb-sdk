package model

type ApiError struct {
	Code int    `json:"code,omitempty"`
	Msg  string `json:"message,omitempty"`
}

// Error implements error interface
func (e ApiError) Error() string {
	return e.Msg
}

func NewApiError(code int, msg string) ApiError {
	return ApiError{Code: code, Msg: msg}
}

func (e ApiError) HasError() bool {
	return e.Code != 0
}

const (
	// Internal error codes (0-5000)
	ErrCodeInternalServerError = 5000

	// Common error codes (6000-9999)
	ErrCodeInvalidRequest = 4000

	///// Business error codes > 10000 /////
	// User error codes (10000-10999)
	ErrCodeUserNotFound   = 10000 // User not found
	ErrCodeUserCreateFail = 10001 // User creation failed

	// JWT authentication error codes (11000-11999)
	ErrCodeJwtGenerationFail = 11000 // JWT generation failed
	ErrCodeJwtInvalid        = 11001 // JWT invalid

	// SIWE authentication error codes (12000-12999)
	ErrCodeSiweInvalidMessage   = 12001 // SIWE message format invalid
	ErrCodeSiweInvalidSignature = 12002 // SIWE signature verification failed
	ErrCodeSiweMessageExpired   = 12003 // SIWE message expired
	ErrCodeSiweMessageNotValid  = 12004 // SIWE message not yet valid
)

func NewErrInvalidRequest(err error) ApiError {
	msg := ""
	if err == nil {
		msg = "invalid request"
	} else {
		msg = err.Error()
	}

	return ApiError{
		Code: ErrCodeInvalidRequest,
		Msg:  msg,
	}
}

func NewErrInternalServerError(err error) ApiError {
	msg := ""
	if err == nil {
		msg = "internal server error"
	} else {
		msg = err.Error()
	}

	return ApiError{
		Code: ErrCodeInternalServerError,
		Msg:  msg,
	}
}

// SIWE related error constructors
func NewErrSiweInvalidMessage(err error) ApiError {
	msg := "invalid SIWE message"
	if err != nil {
		msg = err.Error()
	}
	return ApiError{Code: ErrCodeSiweInvalidMessage, Msg: msg}
}

func NewErrSiweInvalidSignature(err error) ApiError {
	msg := "SIWE signature verification failed"
	if err != nil {
		msg = err.Error()
	}
	return ApiError{Code: ErrCodeSiweInvalidSignature, Msg: msg}
}

func NewErrSiweMessageExpired() ApiError {
	return ApiError{Code: ErrCodeSiweMessageExpired, Msg: "SIWE message expired"}
}

func NewErrSiweMessageNotValid() ApiError {
	return ApiError{Code: ErrCodeSiweMessageNotValid, Msg: "SIWE message not yet valid"}
}

func NewErrJwtGenerationFail(err error) ApiError {
	msg := "JWT generation failed"
	if err != nil {
		msg = err.Error()
	}
	return ApiError{Code: ErrCodeJwtGenerationFail, Msg: msg}
}

func NewErrJwtInvalid(err error) ApiError {
	msg := "invalid JWT token"
	if err != nil {
		msg = err.Error()
	}
	return ApiError{Code: ErrCodeJwtInvalid, Msg: msg}
}

func NewErrUserNotFound() ApiError {
	return ApiError{Code: ErrCodeUserNotFound, Msg: "user not found"}
}

func NewErrUserCreateFail(err error) ApiError {
	msg := "failed to create user"
	if err != nil {
		msg = err.Error()
	}
	return ApiError{Code: ErrCodeUserCreateFail, Msg: msg}
}
