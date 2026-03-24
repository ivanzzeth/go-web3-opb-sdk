package web3opb

import (
	"fmt"

	"github.com/ivanzzeth/go-web3-opb-sdk/model"
)

// ListMembers lists all members of the project.
func (p *ProjectScope) ListMembers() ([]model.ProjectMember, error) {
	result, err := doGet[[]model.ProjectMember](p.client, p.projectURL("/members"))
	if err != nil {
		return nil, err
	}
	return *result, nil
}

// InviteMember invites a user to the project.
func (p *ProjectScope) InviteMember(req *model.InviteMemberRequest) (*model.InviteMemberResponse, error) {
	return doPost[model.InviteMemberResponse](p.client, p.projectURL("/members/invite"), req)
}

// UpdateMemberRole updates a member's role in the project.
func (p *ProjectScope) UpdateMemberRole(userID, role string) error {
	url := fmt.Sprintf("%s/%s", p.projectURL("/members"), userID)
	_, err := doPut[bool](p.client, url, &model.UpdateMemberRoleRequest{Role: role})
	return err
}

// RemoveMember removes a member from the project.
func (p *ProjectScope) RemoveMember(userID string) error {
	url := fmt.Sprintf("%s/%s", p.projectURL("/members"), userID)
	_, err := doDelete[any](p.client, url)
	return err
}

// AcceptInvitation accepts a project invitation using the token.
func (c *Client) AcceptInvitation(token string) error {
	url := fmt.Sprintf("%s/api/%s/invitations/%s/accept", c.authBaseURL(), c.version, token)
	_, err := doPost[bool](c, url, nil)
	return err
}
