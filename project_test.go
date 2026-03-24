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

// Fixed test keypairs — must match harness constants.
const (
	defaultAdminKey = "0ff2c38b76723d6a9a4419f76cdf5e5f686683c779c4af6eca00832b4261333f"
	defaultUserKey  = "0b7c6594b9db0acf1c7ccd05d29b80ab00b973e0ea4262f4feebdcaca0a4ca3d"
)

func getBaseURL() string {
	if u := os.Getenv("AUTH_BASE_URL"); u != "" {
		return u
	}
	return "http://localhost:8700"
}

func newAdminClient(t *testing.T) *Client {
	t.Helper()
	key := os.Getenv("ADMIN_PRIVATE_KEY")
	if key == "" {
		key = defaultAdminKey
	}
	client, err := NewClient(
		WithAuth(getBaseURL(), key),
		WithDomain("localhost"),
	)
	require.NoError(t, err)
	return client
}

func newUserClient(t *testing.T) *Client {
	t.Helper()
	key := os.Getenv("USER_PRIVATE_KEY")
	if key == "" {
		key = defaultUserKey
	}
	client, err := NewClient(
		WithAuth(getBaseURL(), key),
		WithDomain("localhost"),
	)
	require.NoError(t, err)
	return client
}

func newRandomClient(t *testing.T) *Client {
	t.Helper()
	pk, _, err := GenerateEthPrivateKey()
	require.NoError(t, err)
	client, err := NewClient(
		WithAuth(getBaseURL(), hex.EncodeToString(pk.D.Bytes())),
		WithDomain("localhost"),
	)
	require.NoError(t, err)
	return client
}

func TestProject_CRUD(t *testing.T) {
	admin := newAdminClient(t)

	// Create
	project, err := admin.CreateProject(&model.CreateProjectRequest{
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
	ps := admin.Project(pid)

	// Get
	fetched, err := ps.Get()
	require.NoError(t, err)
	assert.Equal(t, project.ID, fetched.ID)

	// Update
	newName := "SDK E2E Updated"
	updated, err := ps.Update(&model.UpdateProjectRequest{Name: &newName})
	require.NoError(t, err)
	assert.Equal(t, "SDK E2E Updated", updated.Name)

	// List
	list, err := admin.ListProjects(1, 10)
	require.NoError(t, err)
	assert.NotNil(t, list)

	// Delete
	err = ps.Delete()
	require.NoError(t, err)
}

func TestProject_APIKeys(t *testing.T) {
	admin := newAdminClient(t)

	project, err := admin.CreateProject(&model.CreateProjectRequest{
		Name: "API Key Test", Slug: "apikey-test",
	})
	require.NoError(t, err)
	ps := admin.Project(fmt.Sprintf("%d", project.ID))
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
	admin := newAdminClient(t)

	project, err := admin.CreateProject(&model.CreateProjectRequest{
		Name: "Member Test", Slug: "member-test",
	})
	require.NoError(t, err)
	ps := admin.Project(fmt.Sprintf("%d", project.ID))
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

	// Accept with a random user
	randomUser := newRandomClient(t)
	err = randomUser.AcceptInvitation(invResp.Token)
	require.NoError(t, err)

	// List members — should have 2
	members, err = ps.ListMembers()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(members), 2)
}

func TestProject_Users(t *testing.T) {
	admin := newAdminClient(t)

	project, err := admin.CreateProject(&model.CreateProjectRequest{
		Name: "User Test", Slug: "user-reg-test",
	})
	require.NoError(t, err)
	ps := admin.Project(fmt.Sprintf("%d", project.ID))
	defer ps.Delete()

	// Admin creates a user (needs admin role)
	_, addr2, err := GenerateEthPrivateKey()
	require.NoError(t, err)
	userID, err := admin.UserCreate(&model.UserCreateRequest{EthAddress: addr2.Hex()})
	require.NoError(t, err)
	userIDStr := fmt.Sprintf("%d", userID)
	t.Logf("created user: id=%s address=%s", userIDStr, addr2.Hex())

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
	admin := newAdminClient(t)

	project, err := admin.CreateProject(&model.CreateProjectRequest{
		Name: "RBAC Test", Slug: "rbac-test",
	})
	require.NoError(t, err)
	ps := admin.Project(fmt.Sprintf("%d", project.ID))
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
	t.Logf("editor permissions: %d entries", len(perms))

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

	// Assign role to a user (admin creates user first)
	_, addr2, _ := GenerateEthPrivateKey()
	userID, err := admin.UserCreate(&model.UserCreateRequest{EthAddress: addr2.Hex()})
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

	t.Logf("RBAC test complete — sync, assign, revoke all working")
}
