package userclaim

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateUserClaimRequest_Valid(t *testing.T) {
	cases := []string{
		"tier",
		"employee_id",
		"department.name",
		"https://app.example.com/tier",
		"urn:example:claim",
		"_private",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidateUserClaimRequest(UserClaimRequest{Name: name, Value: "x"})
			assert.NoError(t, err)
		})
	}
}

func TestValidateUserClaimRequest_EmptyValueAllowed(t *testing.T) {
	assert.NoError(t, ValidateUserClaimRequest(UserClaimRequest{Name: "tier", Value: ""}))
}

func TestValidateUserClaimRequest_ReservedNames(t *testing.T) {
	for _, name := range []string{"sub", "iss", "aud", "exp", "email", "email_verified", "groups", "role", "scope", "SUB", "Email"} {
		t.Run(name, func(t *testing.T) {
			err := ValidateUserClaimRequest(UserClaimRequest{Name: name, Value: "x"})
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "reserved")
		})
	}
}

func TestValidateUserClaimRequest_InvalidName(t *testing.T) {
	for _, name := range []string{"", "1tier", "has space", "bad$char", "trailing\n"} {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, ValidateUserClaimRequest(UserClaimRequest{Name: name, Value: "x"}))
		})
	}
}

func TestValidateUserClaimRequest_ValueTooLong(t *testing.T) {
	err := ValidateUserClaimRequest(UserClaimRequest{Name: "tier", Value: strings.Repeat("a", maxClaimValueLength+1)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "value is invalid")
}

func TestValidateUserClaimRequest_ValueLengthCountsRunesNotBytes(t *testing.T) {
	// maxClaimValueLength multi-byte runes = 3x that in bytes; must still pass.
	err := ValidateUserClaimRequest(UserClaimRequest{Name: "tier", Value: strings.Repeat("é", maxClaimValueLength)})
	assert.NoError(t, err)
}

func TestIsReservedClaimName(t *testing.T) {
	assert.True(t, IsReservedClaimName("sub"))
	assert.True(t, IsReservedClaimName("  GROUPS  "))
	assert.False(t, IsReservedClaimName("tier"))
}
