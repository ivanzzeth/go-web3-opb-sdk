package web3opb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ivanzzeth/go-web3-opb-sdk/model"
)

// EmailRegister registers a new user with email and password.
// A verification email will be sent to the provided email address.
//
//	err := client.EmailRegister("user@example.com", "securepassword")
func (c *Client) EmailRegister(email, password string) error {
	url := fmt.Sprintf("%s/api/%s/email/register", c.authBaseURL(), c.version)
	reqBody := model.EmailRegisterRequest{
		Email:    email,
		Password: password,
	}
	jsonReq, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonReq))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var apiResp model.ApiResponse[map[string]string]
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return err
	}

	if apiResp.ApiError.HasError() {
		return apiResp.ApiError
	}

	return nil
}

// EmailVerify verifies the email address using the token from verification email.
//
//	err := client.EmailVerify("verification-token-from-email")
func (c *Client) EmailVerify(token string) error {
	url := fmt.Sprintf("%s/api/%s/email/verify?token=%s", c.authBaseURL(), c.version, token)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var apiResp model.ApiResponse[map[string]string]
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return err
	}

	if apiResp.ApiError.HasError() {
		return apiResp.ApiError
	}

	return nil
}

// EmailLogin authenticates with email and password, returns JWT token.
// The email must be verified before login.
//
//	result, err := client.EmailLogin("user@example.com", "securepassword")
//	if err == nil {
//	    client.SetCachedJwtToken(result.Token)
//	}
func (c *Client) EmailLogin(email, password string) (*model.EmailLoginResult, error) {
	url := fmt.Sprintf("%s/api/%s/email/login", c.authBaseURL(), c.version)
	reqBody := model.EmailLoginRequest{
		Email:    email,
		Password: password,
	}
	jsonReq, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonReq))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var apiResp model.ApiResponse[model.EmailLoginResult]
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	if apiResp.ApiError.HasError() {
		return nil, apiResp.ApiError
	}

	return &apiResp.Data, nil
}

// EmailResendVerification resends the verification email.
//
//	err := client.EmailResendVerification("user@example.com")
func (c *Client) EmailResendVerification(email string) error {
	url := fmt.Sprintf("%s/api/%s/email/resend-verification", c.authBaseURL(), c.version)
	reqBody := model.EmailResendVerificationRequest{
		Email: email,
	}
	jsonReq, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonReq))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var apiResp model.ApiResponse[map[string]string]
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return err
	}

	if apiResp.ApiError.HasError() {
		return apiResp.ApiError
	}

	return nil
}
