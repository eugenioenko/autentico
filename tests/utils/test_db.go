package testutils

import (
	"encoding/json"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/require"
)

func WithTestDB(t *testing.T) {
	_, err := db.InitTestDB()
	if err != nil {
		t.Fail()
	}

	t.Cleanup(func() {
		db.CloseDB()
	})
}

// InsertTestClient inserts a minimal active OAuth2 client row for tests.
// redirectURIs is the list of allowed redirect URIs for the client.
func InsertTestClient(t *testing.T, clientID string, redirectURIs []string) {
	t.Helper()
	urisJSON, err := json.Marshal(redirectURIs)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(
		`INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, is_active)
		 VALUES (?, ?, 'Test Client', 'public', ?, TRUE)`,
		"id-"+clientID, clientID, string(urisJSON),
	)
	require.NoError(t, err)
}

// InsertTestUser inserts a minimal valid user row so that foreign-key
// constraints on user_id are satisfied in tests that don't exercise the user
// package directly.
func InsertTestUser(t *testing.T, userID string) {
	t.Helper()
	_, err := db.GetDB().Exec(
		`INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)`,
		userID, "user_"+userID, userID+"@test.com", "hashed",
	)
	require.NoError(t, err)
}
