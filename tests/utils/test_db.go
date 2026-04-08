package testutils

import (
	"encoding/json"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
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
		`INSERT INTO clients (id, client_id, client_name, client_type, redirect_uris, post_logout_redirect_uris, is_active)
		 VALUES (?, ?, 'Test Client', 'public', ?, '[]', TRUE)`,
		"id-"+clientID, clientID, string(urisJSON),
	)
	require.NoError(t, err)
}

// InsertTestConfidentialClient inserts a confidential OAuth2 client with a
// known plaintext secret for testing endpoints that require client auth.
// The secret is bcrypt-hashed before storage, matching production behavior.
func InsertTestConfidentialClient(t *testing.T, clientID, clientSecret string) {
	t.Helper()
	hashed, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.MinCost)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(
		`INSERT INTO clients (id, client_id, client_name, client_secret, client_type, redirect_uris, post_logout_redirect_uris, is_active, scopes, grant_types)
		 VALUES (?, ?, 'Test Confidential Client', ?, 'confidential', '[]', '[]', TRUE, 'openid profile email', '["authorization_code","refresh_token"]')`,
		"id-"+clientID, clientID, string(hashed),
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

// InsertTestGroup inserts a minimal group row for tests.
func InsertTestGroup(t *testing.T, groupID, name string) {
	t.Helper()
	_, err := db.GetDB().Exec(
		`INSERT INTO groups (id, name) VALUES (?, ?)`, groupID, name,
	)
	require.NoError(t, err)
}

// InsertTestGroupMembership inserts a user_groups row for tests.
func InsertTestGroupMembership(t *testing.T, userID, groupID string) {
	t.Helper()
	_, err := db.GetDB().Exec(
		`INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)`, userID, groupID,
	)
	require.NoError(t, err)
}
