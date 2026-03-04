package federation

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestListFederationProviders(t *testing.T) {
	testutils.WithTestDB(t)

	// Insert test providers
	_, err := db.GetDB().Exec(`
		INSERT INTO federation_providers (id, name, issuer, client_id, client_secret, enabled, sort_order)
		VALUES ('p1', 'Provider 1', 'https://issuer1.com', 'c1', 's1', TRUE, 1),
		       ('p2', 'Provider 2', 'https://issuer2.com', 'c2', 's2', FALSE, 2)
	`)
	assert.NoError(t, err)

	providers, err := ListFederationProviders()
	assert.NoError(t, err)
	assert.Len(t, providers, 2)
	assert.Equal(t, "p1", providers[0].ID)
	assert.Equal(t, "p2", providers[1].ID)
}

func TestListEnabledProviderViews(t *testing.T) {
	testutils.WithTestDB(t)

	// Insert test providers
	_, err := db.GetDB().Exec(`
		INSERT INTO federation_providers (id, name, issuer, client_id, client_secret, enabled, sort_order)
		VALUES ('p1', 'Provider 1', 'https://issuer1.com', 'c1', 's1', TRUE, 1),
		       ('p2', 'Provider 2', 'https://issuer2.com', 'c2', 's2', FALSE, 2)
	`)
	assert.NoError(t, err)

	views, err := ListEnabledProviderViews()
	assert.NoError(t, err)
	assert.Len(t, views, 1)
	assert.Equal(t, "p1", views[0].ID)
}

func TestFederationProviderByID(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := db.GetDB().Exec(`
		INSERT INTO federation_providers (id, name, issuer, client_id, client_secret, enabled, sort_order)
		VALUES ('p1', 'Provider 1', 'https://issuer1.com', 'c1', 's1', TRUE, 1)
	`)
	assert.NoError(t, err)

	p, err := FederationProviderByID("p1")
	assert.NoError(t, err)
	assert.Equal(t, "Provider 1", p.Name)

	p, err = FederationProviderByID("nonexistent")
	assert.Error(t, err)
	assert.Nil(t, p)
}

func TestFederatedIdentitiesByUserID(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "u1")

	_, err := db.GetDB().Exec(`
		INSERT INTO federation_providers (id, name, issuer, client_id, client_secret)
		VALUES ('p1', 'Provider 1', 'https://issuer1.com', 'c1', 's1')
	`)
	assert.NoError(t, err)

	_, err = db.GetDB().Exec(`
		INSERT INTO federated_identities (id, provider_id, provider_user_id, user_id, email)
		VALUES ('fi1', 'p1', 'sub1', 'u1', 'user@test.com')
	`)
	assert.NoError(t, err)

	identities, err := FederatedIdentitiesByUserID("u1")
	assert.NoError(t, err)
	assert.Len(t, identities, 1)
	assert.Equal(t, "fi1", identities[0].ID)
}

func TestFederatedIdentityByProviderAndSub(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "u1")

	_, _ = db.GetDB().Exec(`
		INSERT INTO federation_providers (id, name, issuer, client_id, client_secret)
		VALUES ('p1', 'Provider 1', 'https://issuer1.com', 'c1', 's1')
	`)

	_, _ = db.GetDB().Exec(`
		INSERT INTO federated_identities (id, provider_id, provider_user_id, user_id, email)
		VALUES ('fi1', 'p1', 'sub1', 'u1', 'user@test.com')
	`)

	fi, err := FederatedIdentityByProviderAndSub("p1", "sub1")
	assert.NoError(t, err)
	assert.Equal(t, "fi1", fi.ID)

	_, err = FederatedIdentityByProviderAndSub("p1", "wrong")
	assert.Error(t, err)
}
