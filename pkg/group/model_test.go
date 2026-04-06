package group

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateGroupCreateRequest_Valid(t *testing.T) {
	err := ValidateGroupCreateRequest(GroupCreateRequest{Name: "admins"})
	assert.NoError(t, err)
}

func TestValidateGroupCreateRequest_ValidWithDescription(t *testing.T) {
	err := ValidateGroupCreateRequest(GroupCreateRequest{Name: "admins", Description: "Admin group"})
	assert.NoError(t, err)
}

func TestValidateGroupCreateRequest_ValidChars(t *testing.T) {
	for _, name := range []string{"my-group", "my_group", "Group123", "A"} {
		err := ValidateGroupCreateRequest(GroupCreateRequest{Name: name})
		assert.NoError(t, err, "name %q should be valid", name)
	}
}

func TestValidateGroupCreateRequest_EmptyName(t *testing.T) {
	err := ValidateGroupCreateRequest(GroupCreateRequest{Name: ""})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name is invalid")
}

func TestValidateGroupCreateRequest_NameTooLong(t *testing.T) {
	err := ValidateGroupCreateRequest(GroupCreateRequest{Name: strings.Repeat("a", 101)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name is invalid")
}

func TestValidateGroupCreateRequest_InvalidChars(t *testing.T) {
	for _, name := range []string{"my group", "my.group", "my@group", "admin!"} {
		err := ValidateGroupCreateRequest(GroupCreateRequest{Name: name})
		assert.Error(t, err, "name %q should be invalid", name)
	}
}

func TestValidateGroupCreateRequest_DescriptionTooLong(t *testing.T) {
	err := ValidateGroupCreateRequest(GroupCreateRequest{Name: "ok", Description: strings.Repeat("a", 501)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "description is invalid")
}

func TestValidateGroupUpdateRequest_EmptyIsValid(t *testing.T) {
	err := ValidateGroupUpdateRequest(GroupUpdateRequest{})
	assert.NoError(t, err)
}

func TestValidateGroupUpdateRequest_ValidName(t *testing.T) {
	err := ValidateGroupUpdateRequest(GroupUpdateRequest{Name: "new-name"})
	assert.NoError(t, err)
}

func TestValidateGroupUpdateRequest_InvalidName(t *testing.T) {
	err := ValidateGroupUpdateRequest(GroupUpdateRequest{Name: "bad name!"})
	assert.Error(t, err)
}

func TestGroupToResponse(t *testing.T) {
	g := &Group{ID: "id1", Name: "test", Description: "desc"}
	r := g.ToResponse()
	assert.Equal(t, "id1", r.ID)
	assert.Equal(t, "test", r.Name)
	assert.Equal(t, "desc", r.Description)
}
