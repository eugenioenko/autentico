package testutils

import (
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
