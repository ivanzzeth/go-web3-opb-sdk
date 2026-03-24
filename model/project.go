package model

import "time"

// Project represents a tenant/application in the multi-tenant auth system.
type Project struct {
	ID          uint64     `json:"id,string"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Status      string     `json:"status"`
	OwnerUserID uint64     `json:"ownerUserId,string"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	DeletedAt   *time.Time `json:"deletedAt,omitempty"`
}

// Project status constants
const (
	ProjectStatusActive    = "active"
	ProjectStatusSuspended = "suspended"
	ProjectStatusArchived  = "archived"
)

// CreateProjectRequest is the request body for creating a project.
type CreateProjectRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// UpdateProjectRequest is the request body for updating a project.
type UpdateProjectRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

// ProjectAPIKey represents an API key pair for a project.
type ProjectAPIKey struct {
	ID               uint64     `json:"id,string"`
	ProjectID        uint64     `json:"projectId,string"`
	Name             string     `json:"name"`
	ClientID         string     `json:"clientId"`
	ClientSecretHint string     `json:"clientSecretHint"`
	Scopes           string     `json:"scopes,omitempty"`
	AllowedOrigins   string     `json:"allowedOrigins,omitempty"`
	IsActive         bool       `json:"isActive"`
	ExpiresAt        *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt       *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
}

// CreateAPIKeyRequest is the request body for creating an API key.
type CreateAPIKeyRequest struct {
	Name           string `json:"name,omitempty"`
	Scopes         string `json:"scopes,omitempty"`
	AllowedOrigins string `json:"allowedOrigins,omitempty"`
	ExpiresAt      string `json:"expiresAt,omitempty"`
}

// CreateAPIKeyResponse is returned once when an API key is created.
type CreateAPIKeyResponse struct {
	ID               uint64     `json:"id,string"`
	ProjectID        uint64     `json:"projectId,string"`
	Name             string     `json:"name"`
	ClientID         string     `json:"clientId"`
	ClientSecret     string     `json:"clientSecret"`
	ClientSecretHint string     `json:"clientSecretHint"`
	Scopes           string     `json:"scopes,omitempty"`
	AllowedOrigins   string     `json:"allowedOrigins,omitempty"`
	IsActive         bool       `json:"isActive"`
	ExpiresAt        *time.Time `json:"expiresAt,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
}

// RotateAPIKeyResponse is returned when an API key is rotated.
type RotateAPIKeyResponse struct {
	ID               uint64 `json:"id,string"`
	ClientID         string `json:"clientId"`
	ClientSecret     string `json:"clientSecret"`
	ClientSecretHint string `json:"clientSecretHint"`
}

// ProjectMember represents a user's membership in a project.
type ProjectMember struct {
	ID        uint64     `json:"id,string"`
	ProjectID uint64     `json:"projectId,string"`
	UserID    uint64     `json:"userId,string"`
	Role      string     `json:"role"`
	InvitedBy uint64     `json:"invitedBy,omitempty,string"`
	JoinedAt  time.Time  `json:"joinedAt"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
	DeletedAt *time.Time `json:"deletedAt,omitempty"`
}

// Project member role constants
const (
	ProjectRoleOwner  = "owner"
	ProjectRoleAdmin  = "admin"
	ProjectRoleMember = "member"
)

// InviteMemberRequest is the request body for inviting a member.
type InviteMemberRequest struct {
	Email      string `json:"email,omitempty"`
	EthAddress string `json:"ethAddress,omitempty"`
	Role       string `json:"role"`
}

// UpdateMemberRoleRequest is the request body for updating a member's role.
type UpdateMemberRoleRequest struct {
	Role string `json:"role"`
}

// InviteMemberResponse is returned when a member is invited.
type InviteMemberResponse struct {
	InvitationID uint64    `json:"invitationId,string"`
	Token        string    `json:"token"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// ProjectUser represents a global user registered to a project.
type ProjectUser struct {
	ID        uint64     `json:"id,string"`
	ProjectID uint64     `json:"projectId,string"`
	UserID    uint64     `json:"userId,string"`
	CreatedAt time.Time  `json:"createdAt"`
	DeletedAt *time.Time `json:"deletedAt,omitempty"`
}

// RegisterProjectUserRequest is the request body for registering a user to a project.
type RegisterProjectUserRequest struct {
	UserID string `json:"userId"`
}
