package web3opb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ivanzzeth/go-web3-opb-sdk/model"
)

// doRequest executes an HTTP request with Bearer token auth and decodes the response.
func doRequest[T any](c *Client, method, url string, body any) (*T, error) {
	var reqBody *bytes.Buffer
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBytes)
	}

	var httpReq *http.Request
	var err error
	if reqBody != nil {
		httpReq, err = http.NewRequest(method, url, reqBody)
	} else {
		httpReq, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.GetCachedJwtToken())
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	var apiResp model.ApiResponse[T]
	if err := json.NewDecoder(httpResp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if apiResp.ApiError.HasError() {
		return nil, apiResp.ApiError
	}
	return &apiResp.Data, nil
}

// doGet performs an authenticated GET request and decodes the response.
func doGet[T any](c *Client, url string) (*T, error) {
	return doRequest[T](c, http.MethodGet, url, nil)
}

// doPost performs an authenticated POST request with a JSON body and decodes the response.
func doPost[T any](c *Client, url string, body any) (*T, error) {
	return doRequest[T](c, http.MethodPost, url, body)
}

// doPut performs an authenticated PUT request with a JSON body and decodes the response.
func doPut[T any](c *Client, url string, body any) (*T, error) {
	return doRequest[T](c, http.MethodPut, url, body)
}

// doDelete performs an authenticated DELETE request and decodes the response.
func doDelete[T any](c *Client, url string) (*T, error) {
	return doRequest[T](c, http.MethodDelete, url, nil)
}
