package userclaim

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpsertClaim_InsertThenUpdate(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	require.NoError(t, UpsertClaim("user1", "tier", "silver"))

	claims, err := ClaimsByUserID("user1")
	require.NoError(t, err)
	require.Len(t, claims, 1)
	assert.Equal(t, "tier", claims[0].Name)
	assert.Equal(t, "silver", claims[0].Value)
	firstUpdatedAt := claims[0].UpdatedAt

	require.NoError(t, UpsertClaim("user1", "tier", "gold"))

	claims, err = ClaimsByUserID("user1")
	require.NoError(t, err)
	require.Len(t, claims, 1, "upsert must not create a second row")
	assert.Equal(t, "gold", claims[0].Value)
	assert.False(t, claims[0].UpdatedAt.Before(firstUpdatedAt))
}

func TestUpsertClaim_UnknownUser(t *testing.T) {
	testutils.WithTestDB(t)

	err := UpsertClaim("nonexistent", "tier", "gold")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestUpsertClaim_MultipleClaimsPerUser(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	require.NoError(t, UpsertClaim("user1", "tier", "gold"))
	require.NoError(t, UpsertClaim("user1", "region", "eu"))

	claims, err := ClaimsByUserID("user1")
	require.NoError(t, err)
	assert.Len(t, claims, 2)
}
