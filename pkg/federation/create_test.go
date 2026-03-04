package federation

import (
	"database/sql"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestCreateFederationProvider(t *testing.T) {
	testutils.WithTestDB(t)

	p := FederationProvider{
		ID:           "p1",
		Name:         "Provider 1",
		Issuer:       "https://issuer1.com",
		ClientID:     "c1",
		ClientSecret: "s1",
	}

	err := CreateFederationProvider(p)
	assert.NoError(t, err)

	// Verify in DB
	saved, err := FederationProviderByID("p1")
	assert.NoError(t, err)
	assert.Equal(t, "Provider 1", saved.Name)
}

func TestCreateFederatedIdentity(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "u1")

	_, _ = db.GetDB().Exec(`
		INSERT INTO federation_providers (id, name, issuer, client_id, client_secret)
		VALUES ('p1', 'Provider 1', 'https://issuer1.com', 'c1', 's1')
	`)

	fi := FederatedIdentity{
		ID:             "fi1",
		ProviderID:     "p1",
		ProviderUserID: "sub1",
		UserID:         "u1",
		Email:          sql.NullString{String: "user@test.com", Valid: true},
	}

	err := CreateFederatedIdentity(fi)
	assert.NoError(t, err)

	// Verify in DB
	identities, _ := FederatedIdentitiesByUserID("u1")
	assert.Len(t, identities, 1)
	assert.NotEmpty(t, identities[0].ID)
}

func TestCreateFederationProvider_Duplicate(t *testing.T) {
	testutils.WithTestDB(t)

	p := FederationProvider{
		ID:           "p1",
		Name:         "Provider 1",
		Issuer:       "https://issuer1.com",
		ClientID:     "c1",
		ClientSecret: "s1",
	}

	err := CreateFederationProvider(p)
	assert.NoError(t, err)

	err = CreateFederationProvider(p)
	assert.Error(t, err)
}

func TestCreateFederatedIdentity_Duplicate(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "u1")

	// Must create provider first due to FK
	_ = CreateFederationProvider(FederationProvider{
		ID: "p1", Name: "P1", Issuer: "https://iss.com", ClientID: "c", ClientSecret: "s",
	})

	fi := FederatedIdentity{
		ID:             "fi1",
		ProviderID:     "p1",
		ProviderUserID: "sub1",
		UserID:         "u1",
		Email:          sql.NullString{String: "u1@test.com", Valid: true},
	}

	err := CreateFederatedIdentity(fi)
	assert.NoError(t, err)

	err = CreateFederatedIdentity(fi)
	assert.Error(t, err)
}
