# go-web3-opb-sdk

Go SDK for [web3-opb](https://github.com/ivanzzeth/web3-opb) — Web3 One People Business infrastructure.

Provides SIWE authentication, JWT management, project management, RBAC, and multi-service support.

## Install

```bash
go get github.com/ivanzzeth/go-web3-opb-sdk
```

## Quick Start

```go
client, _ := web3opb.NewClient(
    web3opb.WithAuth("https://auth.example.com", "your-eth-private-key-hex"),
    web3opb.WithDomain("your-app.example.com"),
)

// Create a project
project, _ := client.CreateProject(&model.CreateProjectRequest{
    Name: "My App",
    Slug: "my-app",
})

// Manage project resources
ps := client.Project(fmt.Sprintf("%d", project.ID))
ps.CreateAPIKey(&model.CreateAPIKeyRequest{Name: "prod-key"})
ps.InviteMember(&model.InviteMemberRequest{Email: "dev@example.com", Role: "admin"})

// Declarative RBAC
ps.RBAC().Sync(model.RBACConfig{
    Roles: []model.RBACRoleConfig{
        {
            Name: "editor",
            Permissions: []model.RBACPermissionConfig{
                {Resource: "articles", Actions: []string{"create", "read", "update", "delete"}},
            },
        },
        {
            Name: "viewer",
            Permissions: []model.RBACPermissionConfig{
                {Resource: "articles", Actions: []string{"read", "list"}},
            },
        },
    },
})
```

## Multi-Service Support

Register multiple microservices and call them with shared JWT auth:

```go
client, _ := web3opb.NewClient(
    web3opb.WithAuth("http://auth.internal:8080", privateKeyHex),
    web3opb.WithDomain("my-app.example.com"),
    web3opb.WithService("notification", "http://notify.internal:8080"),
    web3opb.WithService("wallet", "http://wallet.internal:8080"),
)

// Typed methods for auth service
client.Project("123").RBAC().Sync(config)

// Generic methods for other services
client.Service("notification").Post("/send", req)
```

## API Overview

### Client Options

| Option | Description |
|--------|-------------|
| `WithAuth(url, key)` | Auth service URL + ETH private key (required) |
| `WithDomain(domain)` | SIWE domain for sign-in |
| `WithService(name, url)` | Register additional microservice |
| `WithVersion(version)` | API version prefix (default "v1") |
| `WithHTTPClient(client)` | Custom http.Client |

### Projects

```go
client.CreateProject(req)             // Create
client.ListProjects(page, size)       // List
client.Project(id).Get()              // Get
client.Project(id).Update(req)        // Update
client.Project(id).Delete()           // Delete
```

### API Keys

```go
ps := client.Project(id)
ps.CreateAPIKey(req)                  // Create (returns secret once)
ps.ListAPIKeys(page, size)            // List
ps.RotateAPIKey(keyID)                // Rotate secret
ps.RevokeAPIKey(keyID)                // Revoke
ps.RevokeAllAPIKeys()                 // Revoke all
```

### Members

```go
ps.ListMembers()                      // List
ps.InviteMember(req)                  // Invite by email/address
ps.UpdateMemberRole(uid, role)        // Change role
ps.RemoveMember(uid)                  // Remove
client.AcceptInvitation(token)        // Accept invitation
```

### Project Users

```go
ps.ListUsers()                        // List registered users
ps.RegisterUser(uid)                  // Register
ps.UnregisterUser(uid)                // Unregister
```

### RBAC

```go
rbac := client.Project(id).RBAC()
rbac.Sync(config)                     // Declarative sync
rbac.GrantPermission(req)             // Grant permission
rbac.GetRoles()                       // List roles
rbac.GetRolePermissions(name)         // Get role permissions
rbac.AssignRole(req)                  // Assign role to user
rbac.RevokeRole(role, uid)            // Revoke role
rbac.GetUserRoles(uid)                // Get user's roles
```

### Gin Middleware

```go
import middleware "github.com/ivanzzeth/go-web3-opb-sdk/middleware/gin"

router.Use(middleware.JwtMiddleware(client))                    // Optional JWT extraction
router.Use(middleware.AuthMiddleware(client, "my-app"))         // Required auth + RBAC
```

## E2E Testing

```bash
bash scripts/e2e.sh
```

## License

MIT
