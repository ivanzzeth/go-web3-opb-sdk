package web3opb

import (
	"fmt"

	"github.com/ivanzzeth/go-web3-opb-sdk/model"
)

// CreateAPIKey creates a new API key for the project.
func (p *ProjectScope) CreateAPIKey(req *model.CreateAPIKeyRequest) (*model.CreateAPIKeyResponse, error) {
	return doPost[model.CreateAPIKeyResponse](p.client, p.projectURL("/api-keys"), req)
}

// ListAPIKeys lists API keys for the project.
func (p *ProjectScope) ListAPIKeys(page, pageSize int) (*model.PaginationResult[model.ProjectAPIKey], error) {
	url := fmt.Sprintf("%s?page=%d&pageSize=%d", p.projectURL("/api-keys"), page, pageSize)
	return doGet[model.PaginationResult[model.ProjectAPIKey]](p.client, url)
}

// RevokeAPIKey revokes a single API key.
func (p *ProjectScope) RevokeAPIKey(keyID string) error {
	url := fmt.Sprintf("%s/%s", p.projectURL("/api-keys"), keyID)
	_, err := doDelete[any](p.client, url)
	return err
}

// RevokeAllAPIKeys revokes all API keys for the project.
func (p *ProjectScope) RevokeAllAPIKeys() error {
	_, err := doDelete[any](p.client, p.projectURL("/api-keys"))
	return err
}

// RotateAPIKey rotates an API key, returning the new secret.
func (p *ProjectScope) RotateAPIKey(keyID string) (*model.RotateAPIKeyResponse, error) {
	url := fmt.Sprintf("%s/%s/rotate", p.projectURL("/api-keys"), keyID)
	return doPost[model.RotateAPIKeyResponse](p.client, url, nil)
}
