package web3opb

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/ivanzzeth/go-web3-opb-sdk/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests require a running auth service at AUTH_BASE_URL (default http://localhost:8700).
// The PRIVATE_KEY_HEX env var must be set to an admin wallet's private key.

func newTestClient(t *testing.T) *Client {
	t.Helper()
	baseURL := os.Getenv("AUTH_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8700"
	}
	privateKeyHex := os.Getenv("PRIVATE_KEY_HEX")
	if privateKeyHex == "" {
		t.Skip("PRIVATE_KEY_HEX not set, skipping integration test")
	}
	client, err := NewClient(
		WithAuth(baseURL, privateKeyHex),
		WithDomain("localhost"),
	)
	require.NoError(t, err)
	return client
}

func TestProject_CRUD(t *testing.T) {
	client := newTestClient(t)

	// Create
	project, err := client.CreateProject(&model.CreateProjectRequest{
		Name:        "SDK E2E Test",
		Slug:        "sdk-e2e-test",
		Description: "created by SDK E2E",
	})
	require.NoError(t, err)
	require.NotNil(t, project)
	assert.NotZero(t, project.ID)
	assert.Equal(t, "SDK E2E Test", project.Name)
	assert.Equal(t, "sdk-e2e-test", project.Slug)
	t.Logf("created project: id=%d slug=%s", project.ID, project.Slug)

	pid := fmt.Sprintf("%d", project.ID)
	ps := client.Project(pid)

	// Get
	fetched, err := ps.Get()
	require.NoError(t, err)
	assert.Equal(t, project.ID, fetched.ID)
	assert.Equal(t, "sdk-e2e-test", fetched.Slug)

	// Update
	newName := "SDK E2E Updated"
	updated, err := ps.Update(&model.UpdateProjectRequest{Name: &newName})
	require.NoError(t, err)
	assert.Equal(t, "SDK E2E Updated", updated.Name)

	// List
	list, err := client.ListProjects(1, 10)
	require.NoError(t, err)
	assert.NotNil(t, list)

	// Delete
	err = ps.Delete()
	require.NoError(t, err)
}

func TestProject_APIKeys(t *testing.T) {
	client := newTestClient(t)

	project, err := client.CreateProject(&model.CreateProjectRequest{
		Name: "API Key Test", Slug: "apikey-test",
	})
	require.NoError(t, err)
	ps := client.Project(fmt.Sprintf("%d", project.ID))
	defer ps.Delete()

	// Create key
	keyResp, err := ps.CreateAPIKey(&model.CreateAPIKeyRequest{Name: "test-key"})
	require.NoError(t, err)
	assert.NotEmpty(t, keyResp.ClientID)
	assert.NotEmpty(t, keyResp.ClientSecret)
	t.Logf("created key: clientId=%s hint=%s", keyResp.ClientID, keyResp.ClientSecretHint)

	keyID := fmt.Sprintf("%d", keyResp.ID)

	// List keys
	keys, err := ps.ListAPIKeys(1, 10)
	require.NoError(t, err)
	assert.NotNil(t, keys)

	// Rotate
	rotated, err := ps.RotateAPIKey(keyID)
	require.NoError(t, err)
	assert.NotEqual(t, keyResp.ClientSecret, rotated.ClientSecret)

	// Revoke
	err = ps.RevokeAPIKey(keyID)
	require.NoError(t, err)
}

func TestProject_Members(t *testing.T) {
	client := newTestClient(t)

	project, err := client.CreateProject(&model.CreateProjectRequest{
		Name: "Member Test", Slug: "member-test",
	})
	require.NoError(t, err)
	ps := client.Project(fmt.Sprintf("%d", project.ID))
	defer ps.Delete()

	// List members — should have owner
	members, err := ps.ListMembers()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(members), 1)

	// Invite member
	invResp, err := ps.InviteMember(&model.InviteMemberRequest{
		Email: "test@e2e.com",
		Role:  "member",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, invResp.Token)
	t.Logf("invitation token: %s", invResp.Token)

	// Accept with a different user
	pk2, _, err := GenerateEthPrivateKey()
	require.NoError(t, err)
	baseURL := os.Getenv("AUTH_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8700"
	}
	client2, err := NewClient(
		WithAuth(baseURL, hex.EncodeToString(pk2.D.Bytes())),
		WithDomain("localhost"),
	)
	require.NoError(t, err)

	err = client2.AcceptInvitation(invResp.Token)
	require.NoError(t, err)

	// List members again — should have 2
	members, err = ps.ListMembers()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(members), 2)
}

func TestProject_Users(t *testing.T) {
	client := newTestClient(t)

	project, err := client.CreateProject(&model.CreateProjectRequest{
		Name: "User Test", Slug: "user-reg-test",
	})
	require.NoError(t, err)
	ps := client.Project(fmt.Sprintf("%d", project.ID))
	defer ps.Delete()

	// Create a user to register
	pk2, addr2, err := GenerateEthPrivateKey()
	require.NoError(t, err)
	_ = pk2

	userID, err := client.UserCreate(&model.UserCreateRequest{EthAddress: addr2.Hex()})
	require.NoError(t, err)
	userIDStr := fmt.Sprintf("%d", userID)

	// Register user to project
	err = ps.RegisterUser(userIDStr)
	require.NoError(t, err)

	// List users
	users, err := ps.ListUsers()
	require.NoError(t, err)
	assert.Len(t, users, 1)

	// Unregister
	err = ps.UnregisterUser(userIDStr)
	require.NoError(t, err)

	users, err = ps.ListUsers()
	require.NoError(t, err)
	assert.Len(t, users, 0)
}

func TestProject_RBAC(t *testing.T) {
	client := newTestClient(t)

	project, err := client.CreateProject(&model.CreateProjectRequest{
		Name: "RBAC Test", Slug: "rbac-test",
	})
	require.NoError(t, err)
	ps := client.Project(fmt.Sprintf("%d", project.ID))
	defer ps.Delete()

	rbac := ps.RBAC()

	// Grant permission
	err = rbac.GrantPermission(&model.GrantPermissionRequest{
		Role:     "editor",
		Resource: "filters",
		Actions:  []string{"read", "create", "update"},
	})
	require.NoError(t, err)

	// Get role permissions
	perms, err := rbac.GetRolePermissions("editor")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(perms), 3)
	t.Logf("editor permissions: %+v", perms)

	// Declarative sync
	err = rbac.Sync(model.RBACConfig{
		Roles: []model.RBACRoleConfig{
			{
				Name: "viewer",
				Permissions: []model.RBACPermissionConfig{
					{Resource: "filters", Actions: []string{"read", "list"}},
				},
			},
			{
				Name: "editor",
				Permissions: []model.RBACPermissionConfig{
					{Resource: "filters", Actions: []string{"read", "list", "create", "update", "delete"}},
					{Resource: "api-keys", Actions: []string{"read"}},
				},
			},
		},
	})
	require.NoError(t, err)

	// Verify sync result
	viewerPerms, err := rbac.GetRolePermissions("viewer")
	require.NoError(t, err)
	assert.Len(t, viewerPerms, 2, "viewer should have 2 permissions (read + list)")

	editorPerms, err := rbac.GetRolePermissions("editor")
	require.NoError(t, err)
	assert.Len(t, editorPerms, 6, "editor should have 6 permissions (5 filters + 1 api-keys)")

	// Assign role to a user
	pk2, addr2, _ := GenerateEthPrivateKey()
	_ = pk2
	userID, err := client.UserCreate(&model.UserCreateRequest{EthAddress: addr2.Hex()})
	require.NoError(t, err)
	userIDStr := fmt.Sprintf("%d", userID)

	err = rbac.AssignRole(&model.AssignRoleRequest{
		UserID: userIDStr,
		Role:   "viewer",
	})
	require.NoError(t, err)

	// Get user roles
	roles, err := rbac.GetUserRoles(userIDStr)
	require.NoError(t, err)
	assert.Contains(t, roles, "viewer")

	// Revoke role
	err = rbac.RevokeRole("viewer", userIDStr)
	require.NoError(t, err)
}
