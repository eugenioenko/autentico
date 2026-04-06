package group

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListGroups_Empty(t *testing.T) {
	testutils.WithTestDB(t)

	groups, err := ListGroups()
	require.NoError(t, err)
	assert.Empty(t, groups)
}

func TestListGroups_Multiple(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = CreateGroup("beta", "")
	_, _ = CreateGroup("alpha", "")

	groups, err := ListGroups()
	require.NoError(t, err)
	assert.Len(t, groups, 2)
	// ordered by name
	assert.Equal(t, "alpha", groups[0].Name)
	assert.Equal(t, "beta", groups[1].Name)
}

func TestGroupByID_Found(t *testing.T) {
	testutils.WithTestDB(t)

	created, _ := CreateGroup("admins", "desc")
	g, err := GroupByID(created.ID)
	require.NoError(t, err)
	assert.Equal(t, "admins", g.Name)
	assert.Equal(t, "desc", g.Description)
}

func TestGroupByID_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := GroupByID("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGroupByName_Found(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = CreateGroup("admins", "")
	g, err := GroupByName("admins")
	require.NoError(t, err)
	assert.Equal(t, "admins", g.Name)
}

func TestGroupByName_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := GroupByName("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGroupsByUserID_WithGroups(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestGroup(t, "g1", "admins")
	testutils.InsertTestGroup(t, "g2", "editors")
	testutils.InsertTestGroupMembership(t, "user1", "g1")
	testutils.InsertTestGroupMembership(t, "user1", "g2")

	groups, err := GroupsByUserID("user1")
	require.NoError(t, err)
	assert.Len(t, groups, 2)
}

func TestGroupsByUserID_NoGroups(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	groups, err := GroupsByUserID("user1")
	require.NoError(t, err)
	assert.Empty(t, groups)
}

func TestGroupNamesByUserID(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestGroup(t, "g1", "admins")
	testutils.InsertTestGroup(t, "g2", "editors")
	testutils.InsertTestGroupMembership(t, "user1", "g1")
	testutils.InsertTestGroupMembership(t, "user1", "g2")

	names, err := GroupNamesByUserID("user1")
	require.NoError(t, err)
	assert.Equal(t, []string{"admins", "editors"}, names)
}

func TestGroupNamesByUserID_NoGroups(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	names, err := GroupNamesByUserID("user1")
	require.NoError(t, err)
	assert.Nil(t, names)
}

func TestMembersByGroupID(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestGroup(t, "g1", "admins")
	testutils.InsertTestGroupMembership(t, "user1", "g1")

	members, err := MembersByGroupID("g1")
	require.NoError(t, err)
	assert.Len(t, members, 1)
	assert.Equal(t, "user1", members[0].UserID)
	assert.Equal(t, "user_user1", members[0].Username)
}

func TestMembersByGroupID_Empty(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestGroup(t, "g1", "admins")
	members, err := MembersByGroupID("g1")
	require.NoError(t, err)
	assert.Empty(t, members)
}
