package testutils

import (
	"autentico/pkg/db"
	"log"
	"testing"
)

func WithTestDB(t *testing.T) {
	_, err := db.InitDB("../../db/test.db")
	if err != nil {
		t.Fail()
	}

	t.Cleanup(func() {
		dropTableSQL := `
			DROP TABLE users;
			DROP TABLE sessions;
			DROP TABLE tokens;
		`
		_, err = db.GetDB().Exec(dropTableSQL)
		if err != nil {
			log.Fatalf("Failed to delete tables. %v", err)
		}
		db.CloseDB()
	})
}
