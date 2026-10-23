package trusteddevice

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestTrustedDeviceCredentialIsSeparateFromPublicID(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "owner")
	device := sampleDevice("public-id", "owner")
	const token = "independent-cookie-secret"
	require.NoError(t, CreateTrustedDevice(device, token))
	var id, hash string
	require.NoError(t, db.GetDB().QueryRow(`SELECT id,token_hash FROM trusted_devices`).Scan(&id, &hash))
	require.Equal(t, device.ID, id)
	require.Equal(t, utils.HashToken(token), hash)
	require.NotEqual(t, token, hash)
	request := func(value string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: CookieName, Value: value})
		return r
	}
	for _, value := range []string{id, hash, "", "other-secret"} {
		require.False(t, IsDeviceTrusted("owner", request(value)))
	}
	require.False(t, IsDeviceTrusted("other-user", request(token)))
	require.True(t, IsDeviceTrusted("owner", request(token)))
	stored, err := TrustedDeviceByTokenIncludingExpired(token)
	require.NoError(t, err)
	require.Equal(t, id, stored.ID)
	require.NoError(t, DeleteTrustedDevice(id))
	require.False(t, IsDeviceTrusted("owner", request(token)))
	device.ExpiresAt = time.Now().Add(-time.Hour)
	require.NoError(t, CreateTrustedDevice(device, token))
	require.False(t, IsDeviceTrusted("owner", request(token)))
}

func TestTrustedDeviceRejectsMissingOrExposedCredential(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "owner")
	device := sampleDevice("public-id", "owner")
	require.Error(t, CreateTrustedDevice(device, ""))
	require.Error(t, CreateTrustedDevice(device, device.ID))
	missingID := device
	missingID.ID = ""
	require.Error(t, CreateTrustedDevice(missingID, "secret"))
	require.NoError(t, CreateTrustedDevice(device, "secret"))
	other := device
	other.ID = "other-id"
	require.Error(t, CreateTrustedDevice(other, "secret"), "the unique credential index must reject duplicate tokens")
}
