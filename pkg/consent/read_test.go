package consent

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetConsent_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	c, err := GetConsent("nonexistent", "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, c)
}

func TestGetConsent_Found(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "user-1")
	testutils.InsertTestClient(t, "client-1", []string{"http://localhost/callback"})

	require.NoError(t, UpsertConsent("user-1", "client-1", "openid"))

	c, err := GetConsent("user-1", "client-1")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "user-1", c.UserID)
	assert.Equal(t, "client-1", c.ClientID)
	assert.Equal(t, "openid", c.Scopes)
}
