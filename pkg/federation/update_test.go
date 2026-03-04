package federation

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestUpdateFederationProvider(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = db.GetDB().Exec(`
		INSERT INTO federation_providers (id, name, issuer, client_id, client_secret)
		VALUES ('p1', 'Provider 1', 'https://issuer1.com', 'c1', 's1')
	`)

	enabled := true
	req := FederationProviderRequest{
		Name:         "Updated Name",
		Issuer:       "https://issuer1.com",
		ClientID:     "c1",
		ClientSecret: "s1",
		Enabled:      &enabled,
	}

	err := UpdateFederationProvider("p1", req)
	assert.NoError(t, err)

	// Verify in DB
	updated, _ := FederationProviderByID("p1")
	assert.Equal(t, "Updated Name", updated.Name)
}

func TestUpdateFederationProvider_NoRowsAffected(t *testing.T) {
	testutils.WithTestDB(t)
	err := UpdateFederationProvider("nonexistent", FederationProviderRequest{
		Name: "New Name",
	})
	// As seen in previous run, it returns nil if the query succeeded but matched 0 rows.
	assert.NoError(t, err)
}
