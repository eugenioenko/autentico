package group

import (
	"testing"

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
