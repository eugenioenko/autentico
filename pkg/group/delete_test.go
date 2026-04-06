package group

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteGroup(t *testing.T) {
	testutils.WithTestDB(t)

	g, _ := CreateGroup("admins", "")
	err := DeleteGroup(g.ID)
	require.NoError(t, err)

	_, err = GroupByID(g.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDeleteGroup_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	err := DeleteGroup("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDeleteGroup_CascadesMemberships(t *testing.T) {
	testutils.WithTestDB(t)

	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestGroup(t, "g1", "admins")
	testutils.InsertTestGroupMembership(t, "user1", "g1")

	err := DeleteGroup("g1")
	require.NoError(t, err)

	// Verify membership was cascade-deleted
	var count int
	err = db.GetDB().QueryRow(`SELECT COUNT(*) FROM user_groups WHERE group_id = ?`, "g1").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}
