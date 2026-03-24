package web3opb

import (
	"fmt"
)

// ServiceScope provides methods for calling a registered microservice.
type ServiceScope struct {
	client  *Client
	name    string
	baseURL string
}

// Service returns a ServiceScope for the named microservice.
// The service must have been registered via WithService at construction time.
func (c *Client) Service(name string) *ServiceScope {
	u := c.ServiceURL(name) // panics if not registered
	return &ServiceScope{client: c, name: name, baseURL: u}
}

func (s *ServiceScope) url(path string) string {
	return fmt.Sprintf("%s/api/%s%s", s.baseURL, s.client.version, path)
}

// Get performs an authenticated GET to the service.
func (s *ServiceScope) Get(path string) (any, error) {
	result, err := doGet[any](s.client, s.url(path))
	if err != nil {
		return nil, err
	}
	return *result, nil
}

// Post performs an authenticated POST to the service with a JSON body.
func (s *ServiceScope) Post(path string, body any) (any, error) {
	result, err := doPost[any](s.client, s.url(path), body)
	if err != nil {
		return nil, err
	}
	return *result, nil
}

// Put performs an authenticated PUT to the service with a JSON body.
func (s *ServiceScope) Put(path string, body any) (any, error) {
	result, err := doPut[any](s.client, s.url(path), body)
	if err != nil {
		return nil, err
	}
	return *result, nil
}

// Delete performs an authenticated DELETE to the service.
func (s *ServiceScope) Delete(path string) (any, error) {
	result, err := doDelete[any](s.client, s.url(path))
	if err != nil {
		return nil, err
	}
	return *result, nil
}
