package userclaim

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteClaim_Success(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")
	require.NoError(t, UpsertClaim("user1", "tier", "gold"))

	require.NoError(t, DeleteClaim("user1", "tier"))

	claims, err := ClaimsByUserID("user1")
	require.NoError(t, err)
	assert.Empty(t, claims)
}

func TestDeleteClaim_NotFound(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	err := DeleteClaim("user1", "tier")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "claim not found")
}

func TestDeleteClaim_CascadesOnUserDelete(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")
	require.NoError(t, UpsertClaim("user1", "tier", "gold"))

	_, err := db.GetDB().Exec(`DELETE FROM users WHERE id = ?`, "user1")
	require.NoError(t, err)

	m, err := ClaimMapByUserID("user1")
	require.NoError(t, err)
	assert.Empty(t, m)
}
