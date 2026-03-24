package model

// RBACConfig is the declarative RBAC configuration for a project domain.
type RBACConfig struct {
	Roles []RBACRoleConfig `json:"roles" yaml:"roles"`
}

// RBACRoleConfig defines a single role and its permissions.
type RBACRoleConfig struct {
	Name        string               `json:"name" yaml:"name"`
	Permissions []RBACPermissionConfig `json:"permissions" yaml:"permissions"`
}

// RBACPermissionConfig defines a permission entry (resource + actions).
type RBACPermissionConfig struct {
	Resource string   `json:"resource" yaml:"resource"`
	Actions  []string `json:"actions" yaml:"actions"`
}
