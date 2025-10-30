package testutils

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
)

func WithTestDB(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fail()
	}

	WithConfigOverride(t, func() {
		config.Values.AuthJwkCertFile = "../../db/jwk_cert.pem"
	})

	t.Cleanup(func() {
		db.CloseDB()
	})
}
