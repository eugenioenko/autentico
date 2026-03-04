package federation

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestDeleteFederationProvider(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = db.GetDB().Exec(`
		INSERT INTO federation_providers (id, name, issuer, client_id, client_secret)
		VALUES ('p1', 'Provider 1', 'https://issuer1.com', 'c1', 's1')
	`)

	err := DeleteFederationProvider("p1")
	assert.NoError(t, err)

	p, err := FederationProviderByID("p1")
	assert.Error(t, err)
	assert.Nil(t, p)
}

func TestDeleteFederatedIdentity(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "u1")

	_, _ = db.GetDB().Exec(`
		INSERT INTO federation_providers (id, name, issuer, client_id, client_secret)
		VALUES ('p1', 'Provider 1', 'https://issuer1.com', 'c1', 's1')
	`)

	fi := FederatedIdentity{
		ProviderID:     "p1",
		ProviderUserID: "sub1",
		UserID:         "u1",
	}
	_ = CreateFederatedIdentity(fi)
	
	identities, _ := FederatedIdentitiesByUserID("u1")
	fiID := identities[0].ID

	err := DeleteFederatedIdentity(fiID)
	assert.NoError(t, err)

	err = DeleteFederatedIdentity(fiID)
	assert.Error(t, err)
	assert.Equal(t, "federated identity not found", err.Error())
}

func TestDeleteFederationProvider_NotFound(t *testing.T) {
	testutils.WithTestDB(t)
	err := DeleteFederationProvider("nonexistent")
	// If it doesn't return error when not found, then it should pass.
	assert.NoError(t, err)
}

func TestDeleteFederatedIdentity_NotFound(t *testing.T) {
	testutils.WithTestDB(t)
	err := DeleteFederatedIdentity("nonexistent")
	assert.Error(t, err)
	assert.Equal(t, "federated identity not found", err.Error())
}
