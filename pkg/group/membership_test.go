package group

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddMember(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestGroup(t, "g1", "admins")

	err := AddMember("g1", "user1")
	require.NoError(t, err)

	members, _ := MembersByGroupID("g1")
	assert.Len(t, members, 1)
	assert.Equal(t, "user1", members[0].UserID)
}

func TestAddMember_AlreadyMember(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestGroup(t, "g1", "admins")
	testutils.InsertTestGroupMembership(t, "user1", "g1")

	err := AddMember("g1", "user1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already a member")
}

func TestAddMember_NonExistentUser(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestGroup(t, "g1", "admins")

	err := AddMember("g1", "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAddMember_NonExistentGroup(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")

	err := AddMember("nonexistent", "user1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRemoveMember(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestGroup(t, "g1", "admins")
	testutils.InsertTestGroupMembership(t, "user1", "g1")

	err := RemoveMember("g1", "user1")
	require.NoError(t, err)

	members, _ := MembersByGroupID("g1")
	assert.Empty(t, members)
}

func TestRemoveMember_NotAMember(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestGroup(t, "g1", "admins")

	err := RemoveMember("g1", "user1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a member")
}
