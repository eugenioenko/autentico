package userclaim

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaimMapByUserID(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")
	require.NoError(t, UpsertClaim("user1", "tier", "gold"))
	require.NoError(t, UpsertClaim("user1", "region", "eu"))

	m, err := ClaimMapByUserID("user1")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"tier": "gold", "region": "eu"}, m)
}

func TestClaimMapByUserID_Empty(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")

	m, err := ClaimMapByUserID("user1")
	require.NoError(t, err)
	assert.Empty(t, m)
}

func TestClaimMapByUserIDs_Batch(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")
	testutils.InsertTestUser(t, "user2")
	require.NoError(t, UpsertClaim("user1", "tier", "gold"))
	require.NoError(t, UpsertClaim("user2", "tier", "silver"))
	require.NoError(t, UpsertClaim("user2", "region", "us"))

	m, err := ClaimMapByUserIDs([]string{"user1", "user2"})
	require.NoError(t, err)
	assert.Equal(t, "gold", m["user1"]["tier"])
	assert.Equal(t, "silver", m["user2"]["tier"])
	assert.Equal(t, "us", m["user2"]["region"])
}

func TestClaimMapByUserIDs_EmptyInput(t *testing.T) {
	testutils.WithTestDB(t)

	m, err := ClaimMapByUserIDs(nil)
	require.NoError(t, err)
	assert.Empty(t, m)
}

func TestClaimsByUserID_OrderedByName(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user1")
	require.NoError(t, UpsertClaim("user1", "zeta", "1"))
	require.NoError(t, UpsertClaim("user1", "alpha", "2"))

	claims, err := ClaimsByUserID("user1")
	require.NoError(t, err)
	require.Len(t, claims, 2)
	assert.Equal(t, "alpha", claims[0].Name)
	assert.Equal(t, "zeta", claims[1].Name)
}
