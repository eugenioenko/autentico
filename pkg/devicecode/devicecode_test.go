package devicecode

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAndReadDeviceCode(t *testing.T) {
	testutils.WithTestDB(t)

	dc := DeviceCode{
		Code:            "test-device-code-123",
		UserCode:        "BCDFGHJK",
		ClientID:        "test-client",
		Scope:           "openid profile",
		ExpiresAt:       time.Now().Add(10 * time.Minute),
		IntervalSeconds: 5,
		Status:          "pending",
	}

	err := CreateDeviceCode(dc)
	require.NoError(t, err)

	// Read by code
	found, err := DeviceCodeByCode("test-device-code-123")
	require.NoError(t, err)
	assert.Equal(t, "BCDFGHJK", found.UserCode)
	assert.Equal(t, "test-client", found.ClientID)
	assert.Equal(t, "openid profile", found.Scope)
	assert.Equal(t, "pending", found.Status)
	assert.Equal(t, 5, found.IntervalSeconds)

	// Read by user code
	found2, err := DeviceCodeByUserCode("BCDFGHJK")
	require.NoError(t, err)
	assert.Equal(t, "test-device-code-123", found2.Code)
}

func TestDeviceCodeByCode_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := DeviceCodeByCode("nonexistent")
	assert.Error(t, err)
}

func TestDeviceCodeByUserCode_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := DeviceCodeByUserCode("ZZZZZZZZ")
	assert.Error(t, err)
}

func TestAuthorizeDeviceCode(t *testing.T) {
	testutils.WithTestDB(t)

	usr, err := user.CreateUser("deviceuser", "password123", "device@test.com")
	require.NoError(t, err)

	dc := DeviceCode{
		Code:            "auth-test-code",
		UserCode:        "LMNPQRST",
		ClientID:        "test-client",
		Scope:           "openid",
		ExpiresAt:       time.Now().Add(10 * time.Minute),
		IntervalSeconds: 5,
		Status:          "pending",
	}
	require.NoError(t, CreateDeviceCode(dc))

	err = AuthorizeDeviceCode("LMNPQRST", usr.ID)
	require.NoError(t, err)

	found, err := DeviceCodeByUserCode("LMNPQRST")
	require.NoError(t, err)
	assert.Equal(t, "authorized", found.Status)
	assert.NotNil(t, found.UserID)
	assert.Equal(t, usr.ID, *found.UserID)
}

func TestDenyDeviceCode(t *testing.T) {
	testutils.WithTestDB(t)

	dc := DeviceCode{
		Code:            "deny-test-code",
		UserCode:        "VWXZBCDF",
		ClientID:        "test-client",
		Scope:           "openid",
		ExpiresAt:       time.Now().Add(10 * time.Minute),
		IntervalSeconds: 5,
		Status:          "pending",
	}
	require.NoError(t, CreateDeviceCode(dc))

	err := DenyDeviceCode("VWXZBCDF")
	require.NoError(t, err)

	found, err := DeviceCodeByUserCode("VWXZBCDF")
	require.NoError(t, err)
	assert.Equal(t, "denied", found.Status)
}

func TestAuthorizeDeviceCode_NotPending(t *testing.T) {
	testutils.WithTestDB(t)

	dc := DeviceCode{
		Code:            "already-denied-code",
		UserCode:        "GHJKLMNP",
		ClientID:        "test-client",
		Scope:           "openid",
		ExpiresAt:       time.Now().Add(10 * time.Minute),
		IntervalSeconds: 5,
		Status:          "pending",
	}
	require.NoError(t, CreateDeviceCode(dc))

	// Deny it first
	require.NoError(t, DenyDeviceCode("GHJKLMNP"))

	// Try to authorize — should not change (WHERE status = 'pending')
	err := AuthorizeDeviceCode("GHJKLMNP", "user-456")
	require.NoError(t, err) // no SQL error, but 0 rows affected

	found, err := DeviceCodeByUserCode("GHJKLMNP")
	require.NoError(t, err)
	assert.Equal(t, "denied", found.Status)
}

func TestUpdateLastPolledAt(t *testing.T) {
	testutils.WithTestDB(t)

	dc := DeviceCode{
		Code:            "poll-test-code",
		UserCode:        "QRSTVWXZ",
		ClientID:        "test-client",
		Scope:           "openid",
		ExpiresAt:       time.Now().Add(10 * time.Minute),
		IntervalSeconds: 5,
		Status:          "pending",
	}
	require.NoError(t, CreateDeviceCode(dc))

	now := time.Now()
	err := UpdateLastPolledAt("poll-test-code", now)
	require.NoError(t, err)

	found, err := DeviceCodeByCode("poll-test-code")
	require.NoError(t, err)
	assert.NotNil(t, found.LastPolledAt)
}
