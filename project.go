package web3opb

import (
	"fmt"

	"github.com/ivanzzeth/go-web3-opb-sdk/model"
)

// ProjectScope provides project-scoped API methods.
type ProjectScope struct {
	client    *Client
	projectID string
}

// Project returns a ProjectScope for the given project ID.
func (c *Client) Project(projectID string) *ProjectScope {
	return &ProjectScope{client: c, projectID: projectID}
}

// projectURL builds a URL for a project-scoped endpoint.
func (p *ProjectScope) projectURL(path string) string {
	if path == "" {
		return fmt.Sprintf("%s/api/%s/projects/%s", p.client.authBaseURL(), p.client.version, p.projectID)
	}
	return fmt.Sprintf("%s/api/%s/projects/%s%s", p.client.authBaseURL(), p.client.version, p.projectID, path)
}

// --- Project CRUD ---

// CreateProject creates a new project.
func (c *Client) CreateProject(req *model.CreateProjectRequest) (*model.Project, error) {
	url := fmt.Sprintf("%s/api/%s/projects", c.authBaseURL(), c.version)
	return doPost[model.Project](c, url, req)
}

// ListProjects lists projects for the current user.
func (c *Client) ListProjects(page, pageSize int) (*model.PaginationResult[model.Project], error) {
	url := fmt.Sprintf("%s/api/%s/projects?page=%d&pageSize=%d", c.authBaseURL(), c.version, page, pageSize)
	return doGet[model.PaginationResult[model.Project]](c, url)
}

// Get retrieves the project details.
func (p *ProjectScope) Get() (*model.Project, error) {
	return doGet[model.Project](p.client, p.projectURL(""))
}

// Update updates the project.
func (p *ProjectScope) Update(req *model.UpdateProjectRequest) (*model.Project, error) {
	return doPut[model.Project](p.client, p.projectURL(""), req)
}

// Delete deletes the project.
func (p *ProjectScope) Delete() error {
	_, err := doDelete[any](p.client, p.projectURL(""))
	return err
}
