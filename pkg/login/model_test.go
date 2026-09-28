package login

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestValidateLoginRequest_NativeRedirectURI(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.ValidationMinUsernameLength = 1
		config.Values.ValidationMaxUsernameLength = 255
		config.Values.ValidationMinPasswordLength = 1
		config.Values.ValidationMaxPasswordLength = 255

		req := LoginRequest{
			Username:    "testuser",
			Password:    "password123",
			RedirectURI: "oc://ios.opencloud.eu",
		}

		assert.NoError(t, ValidateLoginRequest(req))
	})
}
