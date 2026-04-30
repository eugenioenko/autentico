package consent

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpsertConsent(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")
	testutils.InsertTestClient(t, "client-1", []string{"http://localhost/callback"})

	err := UpsertConsent("user-1", "client-1", "openid profile")
	require.NoError(t, err)

	c, err := GetConsent("user-1", "client-1")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "openid profile", c.Scopes)
}

func TestUpsertConsent_UpdatesExisting(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")
	testutils.InsertTestClient(t, "client-1", []string{"http://localhost/callback"})

	require.NoError(t, UpsertConsent("user-1", "client-1", "openid"))
	require.NoError(t, UpsertConsent("user-1", "client-1", "openid profile email"))

	c, err := GetConsent("user-1", "client-1")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "openid profile email", c.Scopes)
}
