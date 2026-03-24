package web3opb

import (
	"fmt"

	"github.com/ivanzzeth/go-web3-opb-sdk/model"
)

// ProjectRBACScope provides project-scoped RBAC methods.
type ProjectRBACScope struct {
	client    *Client
	projectID string
}

// RBAC returns a ProjectRBACScope for project-level RBAC operations.
func (p *ProjectScope) RBAC() *ProjectRBACScope {
	return &ProjectRBACScope{client: p.client, projectID: p.projectID}
}

func (r *ProjectRBACScope) rbacURL(path string) string {
	if path == "" {
		return fmt.Sprintf("%s/api/%s/projects/%s/rbac", r.client.authBaseURL(), r.client.version, r.projectID)
	}
	return fmt.Sprintf("%s/api/%s/projects/%s/rbac%s", r.client.authBaseURL(), r.client.version, r.projectID, path)
}

// Sync performs a declarative sync of RBAC roles and permissions.
// It diffs the current state against the desired config and applies changes.
func (r *ProjectRBACScope) Sync(config model.RBACConfig) error {
	_, err := doPut[bool](r.client, r.rbacURL("/config"), &config)
	return err
}

// GetRoles returns all roles in the project domain.
func (r *ProjectRBACScope) GetRoles() ([]string, error) {
	result, err := doGet[[]string](r.client, r.rbacURL("/roles"))
	if err != nil {
		return nil, err
	}
	return *result, nil
}

// GetRolePermissions returns all permissions for a role in the project domain.
func (r *ProjectRBACScope) GetRolePermissions(name string) ([]*model.RolePermission, error) {
	url := fmt.Sprintf("%s/%s/permissions", r.rbacURL("/roles"), name)
	result, err := doGet[model.GetRolePermissionsResponse](r.client, url)
	if err != nil {
		return nil, err
	}
	return result.Permissions, nil
}

// AssignRole assigns a role to a user in the project domain.
func (r *ProjectRBACScope) AssignRole(req *model.AssignRoleRequest) error {
	_, err := doPost[bool](r.client, r.rbacURL("/roles/assign"), req)
	return err
}

// RevokeRole removes a role from a user in the project domain.
func (r *ProjectRBACScope) RevokeRole(roleName, userID string) error {
	url := fmt.Sprintf("%s/%s/users/%s", r.rbacURL("/roles"), roleName, userID)
	_, err := doDelete[bool](r.client, url)
	return err
}

// GrantPermission grants a permission to a role in the project domain.
func (r *ProjectRBACScope) GrantPermission(req *model.GrantPermissionRequest) error {
	_, err := doPost[bool](r.client, r.rbacURL("/roles/permissions/grant"), req)
	return err
}

// GetUserRoles returns all roles for a user in the project domain.
func (r *ProjectRBACScope) GetUserRoles(userID string) ([]string, error) {
	url := fmt.Sprintf("%s/%s", r.rbacURL("/roles/users"), userID)
	result, err := doGet[model.GetUserRolesResponse](r.client, url)
	if err != nil {
		return nil, err
	}
	return result.Roles, nil
}
