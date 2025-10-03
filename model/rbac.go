package model

type CreateRoleRequest struct {
	Name string `json:"name" binding:"required"`
}

type GetRolesResponse struct {
	Roles []string `json:"roles" binding:"required"`
}

type GrantPermissionRequest struct {
	Role    string   `json:"role" binding:"required"`
	Path    string   `json:"path" binding:"required"`
	Methods []string `json:"methods" binding:"required"`
}

type GetRolePermissionsResponse struct {
	Permissions []*RolePermission `json:"permissions" binding:"required"`
}

type AssignRoleRequest struct {
	UserID string `json:"userId" binding:"required"`
	Role   string `json:"role" binding:"required"`
}

type RolePermission struct {
	Role   string `json:"role" binding:"required"`
	Path   string `json:"path" binding:"required"`
	Method string `json:"method" binding:"required"`
}

type RoleHierarchy struct {
	ChildRole  string `json:"childRole" binding:"required"`
	ParentRole string `json:"parentRole" binding:"required"`
}

type RoleHierarchyRequest struct {
	RoleHierarchy []RoleHierarchy `json:"roleHierarchy" binding:"required"`
}
