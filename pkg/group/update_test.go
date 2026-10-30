package group

import (
	"strings"
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateGroup_Name(t *testing.T) {
	testutils.WithTestDB(t)

	g, _ := CreateGroup("admins", "desc")
	err := UpdateGroup(g.ID, GroupUpdateRequest{Name: "superadmins"})
	require.NoError(t, err)

	updated, _ := GroupByID(g.ID)
	assert.Equal(t, "superadmins", updated.Name)
	assert.Equal(t, "desc", updated.Description)
}

func TestUpdateGroup_ValidatesDirectWritesWithoutMutation(t *testing.T) {
	testutils.WithTestDB(t)
	original, err := CreateGroup("a", "original")
	require.NoError(t, err)
	for _, input := range []GroupUpdateRequest{
		{Name: "a.b", Description: "attempted change"}, {Name: "has space"},
		{Name: strings.Repeat("a", 101)}, {Name: "valid", Description: strings.Repeat("d", 501)},
	} {
		require.Error(t, UpdateGroup(original.ID, input))
		current, err := GroupByID(original.ID)
		require.NoError(t, err)
		require.Equal(t, original.Name, current.Name)
		require.Equal(t, original.Description, current.Description)
		require.True(t, original.UpdatedAt.Equal(current.UpdatedAt))
	}
}

func TestUpdateGroup_Description(t *testing.T) {
	testutils.WithTestDB(t)

	g, _ := CreateGroup("admins", "old")
	err := UpdateGroup(g.ID, GroupUpdateRequest{Description: "new"})
	require.NoError(t, err)

	updated, _ := GroupByID(g.ID)
	assert.Equal(t, "admins", updated.Name)
	assert.Equal(t, "new", updated.Description)
}

func TestUpdateGroup_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	err := UpdateGroup("nonexistent", GroupUpdateRequest{Name: "x"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestUpdateGroup_DuplicateName(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = CreateGroup("admins", "")
	g2, _ := CreateGroup("editors", "")
	err := UpdateGroup(g2.ID, GroupUpdateRequest{Name: "admins"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "UNIQUE constraint")
}
