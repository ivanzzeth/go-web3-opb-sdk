package web3opb

import (
	"encoding/hex"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/ivanzzeth/go-web3-opb-sdk/model"
	"github.com/spruceid/siwe-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewApiClient(t *testing.T) {
	baseURL := "http://localhost:8700"
	privateKey, address, err := GenerateEthPrivateKey()
	assert.NoError(t, err)
	assert.NotNil(t, privateKey)
	assert.NotNil(t, address)

	privateKeyHex := hex.EncodeToString(privateKey.D.Bytes())

	apiClient, err := NewApiClient(baseURL, "localhost", "v1", "", privateKeyHex)
	assert.NoError(t, err)
	assert.NotNil(t, apiClient)

	nonce, err := apiClient.SiweGetNonce()
	assert.NoError(t, err)
	assert.NotEmpty(t, nonce)

	// Test SiweMessage
	siweMessage, err := siwe.InitMessage("localhost", address.Hex(), baseURL, nonce, nil)
	assert.NoError(t, err)
	assert.NotNil(t, siweMessage)

	siweMessageModel, err := apiClient.SiweSignMessage(siweMessage)
	assert.NoError(t, err)
	assert.NotNil(t, siweMessageModel)

	siweAuthResult, err := apiClient.SiweVerify(siweMessageModel)
	assert.NoError(t, err)
	assert.NotNil(t, siweAuthResult)

	jwtResult, err := apiClient.JwtVerify(&model.JwtVerifyRequest{Token: siweAuthResult.Token})
	assert.NoError(t, err)
	assert.NotNil(t, jwtResult)
	assert.True(t, jwtResult.Valid)
	assert.Equal(t, address.Hex(), jwtResult.Payload["ethAddress"])
	assert.Equal(t, "localhost", jwtResult.Payload["domain"])
	assert.Equal(t, strconv.FormatUint(siweAuthResult.User.UserID, 10), jwtResult.Payload["userId"])

	jwtResult, err = apiClient.JwtVerifyLocally(&model.JwtVerifyRequest{Token: siweAuthResult.Token})
	assert.NoError(t, err)
	assert.NotNil(t, jwtResult)
	assert.True(t, jwtResult.Valid)
	assert.Equal(t, address.Hex(), jwtResult.Payload["ethAddress"])
	assert.Equal(t, "localhost", jwtResult.Payload["domain"])
	assert.Equal(t, strconv.FormatUint(siweAuthResult.User.UserID, 10), jwtResult.Payload["userId"])

	user, err := apiClient.UserGetByID(siweAuthResult.User.UserID)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, siweAuthResult.User.UserID, user.ID)

	// Test normal users can't get other users' information
	user, err = apiClient.UserGetByEthWallet(address.Hex())
	assert.Error(t, err)
	assert.Nil(t, user)
}

func TestClient_SignIn(t *testing.T) {
	baseURL := "http://localhost:8700"
	privateKey, address, err := GenerateEthPrivateKey()
	assert.NoError(t, err)
	assert.NotNil(t, privateKey)
	assert.NotNil(t, address)

	privateKeyHex := hex.EncodeToString(privateKey.D.Bytes())

	apiClient, err := NewApiClient(baseURL, "localhost", "v1", "", privateKeyHex)
	assert.NoError(t, err)
	assert.NotNil(t, apiClient)

	jwtToken, err := apiClient.SignIn()
	assert.NoError(t, err)
	assert.NotEmpty(t, jwtToken)

	jwtResult, err := apiClient.JwtVerify(&model.JwtVerifyRequest{Token: jwtToken})
	assert.NoError(t, err)
	assert.NotNil(t, jwtResult)
	assert.True(t, jwtResult.Valid)
	t.Logf("jwtToken: %s", jwtToken)

	// Refresh token
	refreshJwtToken, err := apiClient.JwtRefresh(&model.JwtRefreshRequest{Token: jwtToken})
	assert.NoError(t, err)
	assert.NotEmpty(t, refreshJwtToken)
	assert.NotEqual(t, jwtToken, refreshJwtToken.Token)
	t.Logf("refresh jwtToken: %s", refreshJwtToken.Token)

	// Let the token invalid
	originJwtToken := jwtToken
	jwtToken = "invalid"
	apiClient.cachedJwtToken = jwtToken
	jwtResult, err = apiClient.JwtVerify(&model.JwtVerifyRequest{Token: jwtToken})
	assert.Error(t, err)
	assert.Nil(t, jwtResult)
	t.Logf("invalidate jwtToken")

	// Get cached jwt token
	time.Sleep(1 * time.Second)
	cachedJwtToken := apiClient.GetCachedJwtToken()
	assert.NotEmpty(t, cachedJwtToken)
	assert.NotEqual(t, jwtToken, cachedJwtToken)
	assert.NotEqual(t, originJwtToken, cachedJwtToken)
}

func TestClient_RBAC(t *testing.T) {
	baseURL := "http://localhost:8700"
	privateKeyHex := os.Getenv("PRIVATE_KEY_HEX")
	assert.NotEmpty(t, privateKeyHex)

	_, testAddress, err := GenerateEthPrivateKey()
	assert.NoError(t, err)

	apiClient, err := NewApiClient(baseURL, "localhost", "v1", "", privateKeyHex)
	assert.NoError(t, err)

	createRoleResp, err := apiClient.CreateRole(&model.CreateRoleRequest{Name: "test"})
	assert.NoError(t, err)
	assert.True(t, createRoleResp)

	getRolesResp, err := apiClient.GetRoles()
	assert.NoError(t, err)
	assert.NotEmpty(t, getRolesResp)

	getRolePermissionsResp, err := apiClient.GetRolePermissions("test")
	assert.NoError(t, err)
	assert.Empty(t, getRolePermissionsResp)

	deleteRoleResp, err := apiClient.DeleteRole("test")
	assert.NoError(t, err)
	assert.True(t, deleteRoleResp)

	assignRoleResp, err := apiClient.AssignRole(&model.AssignRoleRequest{UserID: "1", Role: "test"})
	assert.Error(t, err)
	assert.False(t, assignRoleResp)

	// We should create the userId first
	userId, err := apiClient.UserCreate(&model.UserCreateRequest{EthAddress: testAddress.Hex()})
	assert.NoError(t, err)
	assert.NotZero(t, userId)

	err = apiClient.UserUpdate(userId, &model.UserUpdateRequest{Metadata: map[string]any{
		"email": "test@test.com",
	}})
	assert.NoError(t, err)

	user, err := apiClient.UserGetByID(userId)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "test@test.com", user.Metadata["email"])

	assignRoleResp, err = apiClient.AssignRole(&model.AssignRoleRequest{UserID: strconv.FormatUint(userId, 10), Role: "test"})
	assert.NoError(t, err)
	assert.True(t, assignRoleResp)

	grantRolePathPermissionsResp, err := apiClient.GrantRolePathPermissions(&model.GrantPermissionRequest{Role: "test", Path: "/api/v1/rbac/roles/:name/permissions", Methods: []string{"GET"}})
	assert.NoError(t, err)
	assert.True(t, grantRolePathPermissionsResp)

	// // Check permission
	getRolePermissionsResp, err = apiClient.GetRolePermissions("test")
	assert.NoError(t, err)
	assert.NotEmpty(t, getRolePermissionsResp)
	assert.Equal(t, 1, len(getRolePermissionsResp))
	assert.Equal(t, "test", getRolePermissionsResp[0].Role)
	assert.Equal(t, "/api/v1/rbac/roles/:name/permissions", getRolePermissionsResp[0].Path)
	assert.Equal(t, "GET", getRolePermissionsResp[0].Method)

	// CreateRoleHierarchy
	createRoleHierarchyResp, err := apiClient.CreateRoleHierarchy(&model.RoleHierarchyRequest{RoleHierarchy: []model.RoleHierarchy{{ChildRole: "test", ParentRole: "admin"}}})
	assert.NoError(t, err)
	assert.True(t, createRoleHierarchyResp)

	getRolePermissionsResp, err = apiClient.GetRolePermissions("test")
	require.NoError(t, err)
	require.NotEmpty(t, getRolePermissionsResp)
	require.Less(t, 1, len(getRolePermissionsResp))

	// DeleteRoleHierarchy
	deleteRoleHierarchyResp, err := apiClient.DeleteRoleHierarchy("admin", "test")
	assert.NoError(t, err)
	assert.True(t, deleteRoleHierarchyResp)

	// RemoveUserRole
	removeUserRoleResp, err := apiClient.RemoveUserRole(strconv.FormatUint(userId, 10), "test")
	assert.NoError(t, err)
	assert.True(t, removeUserRoleResp)

	// DeleteRole
	deleteRoleResp, err = apiClient.DeleteRole("test")
	assert.NoError(t, err)
	assert.True(t, deleteRoleResp)

	// Permissions should be empty
	getRolePermissionsResp, err = apiClient.GetRolePermissions("test")
	require.NoError(t, err)
	require.Empty(t, getRolePermissionsResp)
}
