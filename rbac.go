package web3opb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ivanzzeth/go-web3-opb-sdk/model"
)

func (c *Client) CreateRole(req *model.CreateRoleRequest) (bool, error) {
	url := fmt.Sprintf("%s/api/%s/rbac/roles", c.baseURL, c.version)
	jsonReq, err := json.Marshal(req)
	if err != nil {
		return false, err
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonReq))
	if err != nil {
		return false, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.GetCachedJwtToken())

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return false, err
	}
	defer httpResp.Body.Close()

	var createRoleResp model.APIResponse[bool]
	err = json.NewDecoder(httpResp.Body).Decode(&createRoleResp)
	if err != nil {
		return false, err
	}

	if createRoleResp.ApiError.HasError() {
		return false, createRoleResp.ApiError
	}

	return createRoleResp.Data, nil
}

func (c *Client) GetRoles() ([]string, error) {
	url := fmt.Sprintf("%s/api/%s/rbac/roles", c.baseURL, c.version)
	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.GetCachedJwtToken())

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	var getRolesResp model.APIResponse[[]string]
	err = json.NewDecoder(httpResp.Body).Decode(&getRolesResp)
	if err != nil {
		return nil, err
	}

	if getRolesResp.ApiError.HasError() {
		return nil, getRolesResp.ApiError
	}

	return getRolesResp.Data, nil
}

func (c *Client) GetRolePermissions(name string) ([]*model.RolePermission, error) {
	url := fmt.Sprintf("%s/api/%s/rbac/roles/%s/permissions", c.baseURL, c.version, name)
	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.GetCachedJwtToken())

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	var getRolePermissionsResp model.APIResponse[model.GetRolePermissionsResponse]
	err = json.NewDecoder(httpResp.Body).Decode(&getRolePermissionsResp)
	if err != nil {
		return nil, err
	}

	if getRolePermissionsResp.ApiError.HasError() {
		return nil, getRolePermissionsResp.ApiError
	}

	return getRolePermissionsResp.Data.Permissions, nil
}

func (c *Client) DeleteRole(name string) (bool, error) {
	url := fmt.Sprintf("%s/api/%s/rbac/roles/%s", c.baseURL, c.version, name)
	httpReq, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return false, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.GetCachedJwtToken())

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return false, err
	}
	defer httpResp.Body.Close()

	var deleteRoleResp model.APIResponse[bool]
	err = json.NewDecoder(httpResp.Body).Decode(&deleteRoleResp)
	if err != nil {
		return false, err
	}

	if deleteRoleResp.ApiError.HasError() {
		return false, deleteRoleResp.ApiError
	}

	return deleteRoleResp.Data, nil
}

func (c *Client) AssignRole(req *model.AssignRoleRequest) (bool, error) {
	url := fmt.Sprintf("%s/api/%s/rbac/roles/assign", c.baseURL, c.version)
	jsonReq, err := json.Marshal(req)
	if err != nil {
		return false, err
	}
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonReq))
	if err != nil {
		return false, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.GetCachedJwtToken())

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return false, err
	}
	defer httpResp.Body.Close()

	var assignRoleResp model.APIResponse[bool]
	err = json.NewDecoder(httpResp.Body).Decode(&assignRoleResp)
	if err != nil {
		return false, err
	}
	if assignRoleResp.ApiError.HasError() {
		return false, assignRoleResp.ApiError
	}

	return assignRoleResp.Data, nil
}

func (c *Client) GrantRolePathPermissions(req *model.GrantPermissionRequest) (bool, error) {
	url := fmt.Sprintf("%s/api/%s/rbac/roles/permissions/grant", c.baseURL, c.version)
	jsonReq, err := json.Marshal(req)
	if err != nil {
		return false, err
	}
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonReq))
	if err != nil {
		return false, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.GetCachedJwtToken())

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return false, err
	}
	defer httpResp.Body.Close()

	var grantRolePathPermissionsResp model.APIResponse[bool]
	err = json.NewDecoder(httpResp.Body).Decode(&grantRolePathPermissionsResp)
	if err != nil {
		return false, err
	}

	if grantRolePathPermissionsResp.ApiError.HasError() {
		return false, grantRolePathPermissionsResp.ApiError
	}

	return grantRolePathPermissionsResp.Data, nil
}

func (c *Client) RemoveUserRole(userId string, role string) (bool, error) {
	url := fmt.Sprintf("%s/api/%s/rbac/roles/%s/users/%s", c.baseURL, c.version, role, userId)
	httpReq, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return false, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.GetCachedJwtToken())

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return false, err
	}
	defer httpResp.Body.Close()

	var removeUserRoleResp model.APIResponse[bool]
	err = json.NewDecoder(httpResp.Body).Decode(&removeUserRoleResp)
	if err != nil {
		return false, err
	}

	if removeUserRoleResp.ApiError.HasError() {
		return false, removeUserRoleResp.ApiError
	}

	return removeUserRoleResp.Data, nil
}

func (c *Client) CreateRoleHierarchy(req *model.RoleHierarchyRequest) (bool, error) {
	url := fmt.Sprintf("%s/api/%s/rbac/roles/hierarchy", c.baseURL, c.version)
	jsonReq, err := json.Marshal(req)
	if err != nil {
		return false, err
	}
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonReq))
	if err != nil {
		return false, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.GetCachedJwtToken())

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return false, err
	}
	defer httpResp.Body.Close()

	var createRoleHierarchyResp model.APIResponse[bool]
	err = json.NewDecoder(httpResp.Body).Decode(&createRoleHierarchyResp)
	if err != nil {
		return false, err
	}

	if createRoleHierarchyResp.ApiError.HasError() {
		return false, createRoleHierarchyResp.ApiError
	}

	return createRoleHierarchyResp.Data, nil
}

func (c *Client) DeleteRoleHierarchy(parentRole string, childRole string) (bool, error) {
	url := fmt.Sprintf("%s/api/%s/rbac/roles/hierarchy/%s/children/%s", c.baseURL, c.version, parentRole, childRole)
	httpReq, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return false, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.GetCachedJwtToken())

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return false, err
	}
	defer httpResp.Body.Close()

	var deleteRoleHierarchyResp model.APIResponse[bool]
	err = json.NewDecoder(httpResp.Body).Decode(&deleteRoleHierarchyResp)
	if err != nil {
		return false, err
	}

	if deleteRoleHierarchyResp.ApiError.HasError() {
		return false, deleteRoleHierarchyResp.ApiError
	}

	return deleteRoleHierarchyResp.Data, nil
}
