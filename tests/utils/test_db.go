package testutils

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
)

func WithTestDB(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fail()
	}

	t.Cleanup(func() {
		db.CloseDB()
	})
}
