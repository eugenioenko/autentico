package group

import (
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateGroup(t *testing.T) {
	testutils.WithTestDB(t)

	g, err := CreateGroup("admins", "Administrator group")
	require.NoError(t, err)
	assert.NotEmpty(t, g.ID)
	assert.Equal(t, "admins", g.Name)
	assert.Equal(t, "Administrator group", g.Description)
	assert.False(t, g.CreatedAt.IsZero())
	assert.False(t, g.UpdatedAt.IsZero())
}

func TestCreateGroup_ValidatesDirectWrites(t *testing.T) {
	testutils.WithTestDB(t)
	for _, input := range []GroupCreateRequest{
		{Name: "a.b"}, {Name: "has space"}, {Name: ""},
		{Name: strings.Repeat("a", 101)}, {Name: "a", Description: strings.Repeat("d", 501)},
	} {
		created, err := CreateGroup(input.Name, input.Description)
		require.Error(t, err)
		require.Nil(t, created)
	}
	var count int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM groups`).Scan(&count))
	require.Zero(t, count, "invalid direct calls must not persist groups")
	for _, name := range []string{"123", "-team", "_team", strings.Repeat("g", 100)} {
		created, err := CreateGroup(name, "")
		require.NoError(t, err)
		require.Equal(t, name, created.Name)
	}
}

func TestCreateGroup_EmptyDescription(t *testing.T) {
	testutils.WithTestDB(t)

	g, err := CreateGroup("editors", "")
	require.NoError(t, err)
	assert.Equal(t, "", g.Description)
}

func TestCreateGroup_DuplicateName(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := CreateGroup("admins", "first")
	require.NoError(t, err)

	_, err = CreateGroup("admins", "second")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "UNIQUE constraint")
}
