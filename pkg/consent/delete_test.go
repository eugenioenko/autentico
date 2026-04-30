package consent

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteConsentsByClient(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")
	testutils.InsertTestUser(t, "user-2")
	testutils.InsertTestClient(t, "client-1", []string{"http://localhost/callback"})

	require.NoError(t, UpsertConsent("user-1", "client-1", "openid"))
	require.NoError(t, UpsertConsent("user-2", "client-1", "openid profile"))

	require.NoError(t, DeleteConsentsByClient("client-1"))

	c1, _ := GetConsent("user-1", "client-1")
	c2, _ := GetConsent("user-2", "client-1")
	assert.Nil(t, c1)
	assert.Nil(t, c2)
}

func TestDeleteConsentsByUser(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")
	testutils.InsertTestClient(t, "client-1", []string{"http://localhost/callback"})
	testutils.InsertTestClient(t, "client-2", []string{"http://localhost/callback"})

	require.NoError(t, UpsertConsent("user-1", "client-1", "openid"))
	require.NoError(t, UpsertConsent("user-1", "client-2", "openid profile"))

	require.NoError(t, DeleteConsentsByUser("user-1"))

	c1, _ := GetConsent("user-1", "client-1")
	c2, _ := GetConsent("user-1", "client-2")
	assert.Nil(t, c1)
	assert.Nil(t, c2)
}
