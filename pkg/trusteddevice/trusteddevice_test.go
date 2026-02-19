package trusteddevice

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleDevice(id, userID string) TrustedDevice {
	return TrustedDevice{
		ID:         id,
		UserID:     userID,
		DeviceName: "TestBrowser/1.0",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}
}

// --- CreateTrustedDevice ---

func TestCreateTrustedDevice(t *testing.T) {
	testutils.WithTestDB(t)
	dev := sampleDevice("dev-create-1", "user-1")
	err := CreateTrustedDevice(dev)
	require.NoError(t, err)
}

func TestCreateTrustedDeviceDuplicateID(t *testing.T) {
	testutils.WithTestDB(t)
	dev := sampleDevice("dev-dup-1", "user-1")
	require.NoError(t, CreateTrustedDevice(dev))
	err := CreateTrustedDevice(dev)
	assert.Error(t, err)
}

// --- TrustedDeviceByID ---

func TestTrustedDeviceByID(t *testing.T) {
	testutils.WithTestDB(t)
	dev := sampleDevice("dev-read-1", "user-read-1")
	require.NoError(t, CreateTrustedDevice(dev))

	got, err := TrustedDeviceByID("dev-read-1")
	require.NoError(t, err)
	assert.Equal(t, dev.ID, got.ID)
	assert.Equal(t, dev.UserID, got.UserID)
	assert.Equal(t, dev.DeviceName, got.DeviceName)
}

func TestTrustedDeviceByIDNotFound(t *testing.T) {
	testutils.WithTestDB(t)
	_, err := TrustedDeviceByID("does-not-exist")
	assert.Error(t, err)
}

// --- UpdateLastUsed ---

func TestUpdateLastUsed(t *testing.T) {
	testutils.WithTestDB(t)
	dev := sampleDevice("dev-update-1", "user-1")
	require.NoError(t, CreateTrustedDevice(dev))

	err := UpdateLastUsed("dev-update-1")
	require.NoError(t, err)

	got, err := TrustedDeviceByID("dev-update-1")
	require.NoError(t, err)
	assert.Equal(t, "dev-update-1", got.ID)
}

func TestUpdateLastUsedNonexistent(t *testing.T) {
	testutils.WithTestDB(t)
	// No row affected, but UPDATE should not return an error.
	err := UpdateLastUsed("ghost-device")
	assert.NoError(t, err)
}

// --- IsDeviceTrusted ---

func TestIsDeviceTrustedValid(t *testing.T) {
	testutils.WithTestDB(t)
	dev := sampleDevice("dev-trusted-1", "user-trusted-1")
	require.NoError(t, CreateTrustedDevice(dev))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "dev-trusted-1"})

	assert.True(t, IsDeviceTrusted("user-trusted-1", req))
}

func TestIsDeviceTrustedWrongUser(t *testing.T) {
	testutils.WithTestDB(t)
	dev := sampleDevice("dev-trusted-2", "user-a")
	require.NoError(t, CreateTrustedDevice(dev))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "dev-trusted-2"})

	assert.False(t, IsDeviceTrusted("user-b", req))
}

func TestIsDeviceTrustedExpired(t *testing.T) {
	testutils.WithTestDB(t)
	dev := TrustedDevice{
		ID:         "dev-expired-1",
		UserID:     "user-exp-1",
		DeviceName: "TestBrowser",
		ExpiresAt:  time.Now().Add(-1 * time.Hour), // already expired
	}
	require.NoError(t, CreateTrustedDevice(dev))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "dev-expired-1"})

	assert.False(t, IsDeviceTrusted("user-exp-1", req))
}

func TestIsDeviceTrustedNoCookie(t *testing.T) {
	testutils.WithTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.False(t, IsDeviceTrusted("any-user", req))
}

func TestIsDeviceTrustedUnknownToken(t *testing.T) {
	testutils.WithTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "unknown-token"})
	assert.False(t, IsDeviceTrusted("any-user", req))
}

// --- SetCookie / ReadCookie ---

func TestSetCookieAndReadCookie(t *testing.T) {
	w := httptest.NewRecorder()
	SetCookie(w, "device-abc", 30*24*time.Hour)

	resp := w.Result()
	cookies := resp.Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, CookieName, cookies[0].Name)
	assert.Equal(t, "device-abc", cookies[0].Value)
	assert.True(t, cookies[0].HttpOnly)
	assert.Equal(t, int((30 * 24 * time.Hour).Seconds()), cookies[0].MaxAge)
}

func TestReadCookieMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.Equal(t, "", ReadCookie(req))
}

func TestReadCookiePresent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "tok123"})
	assert.Equal(t, "tok123", ReadCookie(req))
}
