package federation

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestSignAndVerifyState(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthCSRFProtectionSecretKey = "test-secret-key-12345678901234567890123456789012"
	})

	state := FederationState{
		ProviderID: "google",
		ClientID:   "client1",
		State:      "random-state",
	}

	signed, err := SignState(state)
	assert.NoError(t, err)
	assert.NotEmpty(t, signed)

	verified, err := VerifyState(signed)
	assert.NoError(t, err)
	assert.Equal(t, state.ProviderID, verified.ProviderID)
	assert.Equal(t, state.ClientID, verified.ClientID)
	assert.Equal(t, state.State, verified.State)
}

func TestVerifyState_Invalid(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthCSRFProtectionSecretKey = "test-secret-key-12345678901234567890123456789012"
	})

	// Invalid format
	_, err := VerifyState("invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "format")

	// Signature mismatch
	state := FederationState{ProviderID: "google"}
	signed, _ := SignState(state)
	_, err = VerifyState(signed + "extra")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature mismatch")
}
