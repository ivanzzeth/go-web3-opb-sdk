package web3opb

import (
	"fmt"

	"github.com/ivanzzeth/go-web3-opb-sdk/model"
)

// ListUsers lists all registered users for the project.
func (p *ProjectScope) ListUsers() ([]model.ProjectUser, error) {
	result, err := doGet[[]model.ProjectUser](p.client, p.projectURL("/users"))
	if err != nil {
		return nil, err
	}
	return *result, nil
}

// RegisterUser registers a global user to the project.
func (p *ProjectScope) RegisterUser(userID string) error {
	_, err := doPost[bool](p.client, p.projectURL("/users"), &model.RegisterProjectUserRequest{UserID: userID})
	return err
}

// UnregisterUser unregisters a user from the project.
func (p *ProjectScope) UnregisterUser(userID string) error {
	url := fmt.Sprintf("%s/%s", p.projectURL("/users"), userID)
	_, err := doDelete[any](p.client, url)
	return err
}
