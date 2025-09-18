package web3opb

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ivanzzeth/go-web3-opb-sdk/model"
)

func (c *ApiClient) UserGetByID(id uint64) (*model.User, error) {
	url := fmt.Sprintf("%s/api/%s/users/%d", c.baseURL, c.version, id)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.GetCachedJwtToken())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// body, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	return nil, err
	// }
	// fmt.Printf("body: %s\n", string(body))
	// return nil, nil
	var userResp model.APIResponse[model.User]
	err = json.NewDecoder(resp.Body).Decode(&userResp)
	if err != nil {
		return nil, err
	}

	if userResp.ApiError.HasError() {
		return nil, userResp.ApiError
	}

	return &userResp.Data, nil
}

func (c *ApiClient) UserGetByEthWallet(address string) (*model.User, error) {
	url := fmt.Sprintf("%s/api/%s/users/eth_wallets/%s", c.baseURL, c.version, address)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.GetCachedJwtToken())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userResp model.APIResponse[model.User]
	err = json.NewDecoder(resp.Body).Decode(&userResp)
	if err != nil {
		return nil, err
	}

	if userResp.ApiError.HasError() {
		return nil, userResp.ApiError
	}

	return &userResp.Data, nil
}

func (c *ApiClient) UserGetEthWallets(id uint64) ([]*model.UserEthWallet, error) {
	url := fmt.Sprintf("%s/api/%s/users/%d/eth_wallets", c.baseURL, c.version, id)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.GetCachedJwtToken())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userEthWalletsResp model.APIResponse[[]*model.UserEthWallet]
	err = json.NewDecoder(resp.Body).Decode(&userEthWalletsResp)
	if err != nil {
		return nil, err
	}

	if userEthWalletsResp.ApiError.HasError() {
		return nil, userEthWalletsResp.ApiError
	}

	return userEthWalletsResp.Data, nil
}

func (c *ApiClient) UserList(listReq *model.UserListRequest) (*model.UserListResponse, error) {
	url := fmt.Sprintf("%s/api/%s/users?page=%d&pageSize=%d", c.baseURL, c.version, listReq.Page, listReq.PageSize)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.GetCachedJwtToken())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userListResp model.APIResponse[model.UserListResponse]
	err = json.NewDecoder(resp.Body).Decode(&userListResp)
	if err != nil {
		return nil, err
	}

	if userListResp.ApiError.HasError() {
		return nil, userListResp.ApiError
	}

	return &userListResp.Data, nil
}
