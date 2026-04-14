package web3opb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ivanzzeth/go-web3-opb-sdk/model"
)

// BindSIWE binds a SIWE wallet to the current user.
// Requires a fresh SIWE signature (proves wallet ownership right now).
// The user must be authenticated (JWT token cached).
//
//	err := client.BindSIWE(siweMessage, signature)
func (c *Client) BindSIWE(siweMessage, signature string) error {
	reqBody := model.BindAuthRequest{
		AuthType:      model.AuthTypeSIWE,
		SiweMessage:   siweMessage,
		SiweSignature: signature,
	}
	return c.bindAuth(&reqBody)
}

// BindOAuth2 binds an OAuth2 account to the current user.
// Requires a fresh auth code from the OAuth2 flow (one-time use).
// The user must be authenticated (JWT token cached).
//
//	err := client.BindOAuth2(authCode)
func (c *Client) BindOAuth2(authCode string) error {
	reqBody := model.BindAuthRequest{
		AuthType: model.AuthTypeOAuth2,
		AuthCode: authCode,
	}
	return c.bindAuth(&reqBody)
}

// BindEmail binds an email account to the current user.
// If the email already exists and the password is correct, merges the accounts.
// If the email doesn't exist, adds it to the current user.
// The user must be authenticated (JWT token cached).
//
//	err := client.BindEmail("user@example.com", "password123")
func (c *Client) BindEmail(email, password string) error {
	reqBody := model.BindAuthRequest{
		AuthType: model.AuthTypeEmail,
		Email:    email,
		Password: password,
	}
	return c.bindAuth(&reqBody)
}

// bindAuth is the internal implementation for all bind operations.
func (c *Client) bindAuth(reqBody *model.BindAuthRequest) error {
	url := fmt.Sprintf("%s/api/%s/bind", c.authBaseURL(), c.version)
	jsonReq, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonReq))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.GetCachedJwtToken())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var apiResp model.ApiResponse[bool]
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return err
	}

	if apiResp.ApiError.HasError() {
		return apiResp.ApiError
	}

	return nil
}
