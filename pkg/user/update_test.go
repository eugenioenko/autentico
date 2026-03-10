package user

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateUser(t *testing.T) {
	testutils.WithTestDB(t)

	u, _ := CreateUser("u1", "p1", "e1@test.com")

	req := UserUpdateRequest{
		GivenName: "John",
	}
	err := UpdateUser(u.ID, req)
	assert.NoError(t, err)

	updated, _ := UserByID(u.ID)
	assert.Equal(t, "John", updated.GivenName)
}

func TestDisableMfa(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := CreateUser("u1", "p1", "e1@test.com")
	_ = SaveTotpSecret(u.ID, "secret")

	err := DisableMfa(u.ID)
	assert.NoError(t, err)

	updated, _ := UserByID(u.ID)
	assert.False(t, updated.TotpVerified)
	assert.Empty(t, updated.TotpSecret)
}

func TestStoreTotpSecretPending(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := CreateUser("u1", "p1", "e1@test.com")

	err := StoreTotpSecretPending(u.ID, "pending-secret")
	assert.NoError(t, err)

	updated, _ := UserByID(u.ID)
	assert.Equal(t, "pending-secret", updated.TotpSecret)
	assert.False(t, updated.TotpVerified)
}

func TestSetRegisteredAt(t *testing.T) {
	testutils.WithTestDB(t)

	ur, err := CreatePasskeyUser("pkuser", "pk@test.com")
	require.NoError(t, err)

	u, _ := UserByID(ur.ID)
	assert.Nil(t, u.RegisteredAt, "should be nil before ceremony completes")

	require.NoError(t, SetRegisteredAt(ur.ID))

	u, _ = UserByID(ur.ID)
	assert.NotNil(t, u.RegisteredAt, "should be set after SetRegisteredAt")
}

func TestUnlockUser(t *testing.T) {
	testutils.WithTestDB(t)
	u, _ := CreateUser("u1", "p1", "e1@test.com")

	err := UnlockUser(u.ID)
	assert.NoError(t, err)
}
