// Proprietary License
//
// All Rights Reserved
//
// Copyright (c) 2025 Ivan Zhang(ivanzz.eth@gmail.com)
//
// THE CONTENTS OF THIS PROJECT ARE PROPRIETARY AND CONFIDENTIAL. UNAUTHORIZED COPYING, TRANSFERRING OR REPRODUCTION OF THE CONTENTS OF THIS PROJECT, VIA ANY MEDIUM IS STRICTLY PROHIBITED.
//
// The receipt or possession of the source code and/or any parts thereof does not convey or imply any right to use them for any purpose other than the purpose for which they were provided to you.
//
// The software is provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and non-infringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software.
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the software.
//
// ### Commercial Use
//
// Commercial use of this software is permitted only with explicit written authorization from the copyright holder. Unauthorized commercial use is strictly prohibited.
//
// ### Contact Information
//
// For inquiries regarding licensing or to obtain authorization for commercial use, please contact +1 (281) 857-9975.
//
// ### License Grant
//
// The copyright holder hereby grants you a non-exclusive, non-transferable, non-sublicensable license to use the software solely for the purposes authorized by the copyright holder. This license is granted on the condition that you comply with all terms and conditions set forth herein.
//
// ### Term and Termination
//
// This license shall remain in effect until terminated by the copyright holder. The copyright holder reserves the right to terminate this license immediately if you fail to comply with any of the terms and conditions set forth herein.

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
