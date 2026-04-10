package testutils

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------- WithTestDB ----------

func TestWithTestDB(t *testing.T) {
	WithTestDB(t)

	// DB should be usable
	d := db.GetDB()
	require.NotNil(t, d)

	var n int
	err := d.QueryRow("SELECT 1").Scan(&n)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

// ---------- WithConfigOverride ----------

func TestWithConfigOverride(t *testing.T) {
	originalURL := config.GetBootstrap().AppURL

	WithConfigOverride(t, func() {
		config.Bootstrap.AppURL = "http://override.test"
	})

	assert.Equal(t, "http://override.test", config.GetBootstrap().AppURL)

	// Cleanup is deferred — we can't test restore within the same test,
	// but we verify the override took effect.
	_ = originalURL
}

// ---------- MockJSONRequest ----------

func TestMockJSONRequest(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}

	body := MockJSONRequest(t, `{"test":true}`, http.MethodPost, "/test", handler)
	assert.Contains(t, string(body), `"ok":true`)
}

// ---------- MockApiRequestWithAuth ----------

func TestMockApiRequestWithAuth(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-token-123", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
	}

	rr := MockApiRequestWithAuth(t, `{}`, http.MethodGet, "/test", handler, "test-token-123")
	assert.Equal(t, http.StatusOK, rr.Code)
}

// ---------- MockFormRequest ----------

func TestMockFormRequest(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		_ = r.ParseForm()
		assert.Equal(t, "admin", r.FormValue("username"))
		assert.Equal(t, "pass123", r.FormValue("password"))
		w.WriteHeader(http.StatusOK)
	}

	rr := MockFormRequest(t, map[string]string{
		"username": "admin",
		"password": "pass123",
	}, http.MethodPost, "/login", handler)
	assert.Equal(t, http.StatusOK, rr.Code)
}

// ---------- MockFormRequestWithBasicAuth ----------

func TestMockFormRequestWithBasicAuth(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		clientID, clientSecret, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "my-client", clientID)
		assert.Equal(t, "my-secret", clientSecret)
		w.WriteHeader(http.StatusOK)
	}

	rr := MockFormRequestWithBasicAuth(t, map[string]string{
		"grant_type": "authorization_code",
	}, http.MethodPost, "/token", handler, "my-client", "my-secret")
	assert.Equal(t, http.StatusOK, rr.Code)
}

// ---------- InsertTestClient ----------

func TestInsertTestClient(t *testing.T) {
	WithTestDB(t)

	InsertTestClient(t, "test-client", []string{"http://localhost/callback"})

	d := db.GetDB()
	var clientID string
	err := d.QueryRow("SELECT client_id FROM clients WHERE client_id = ?", "test-client").Scan(&clientID)
	require.NoError(t, err)
	assert.Equal(t, "test-client", clientID)
}

// ---------- InsertTestConfidentialClient ----------

func TestInsertTestConfidentialClient(t *testing.T) {
	WithTestDB(t)

	InsertTestConfidentialClient(t, "conf-client", "conf-secret")

	d := db.GetDB()
	var clientType string
	err := d.QueryRow("SELECT client_type FROM clients WHERE client_id = ?", "conf-client").Scan(&clientType)
	require.NoError(t, err)
	assert.Equal(t, "confidential", clientType)
}

// ---------- InsertTestUser ----------

func TestInsertTestUser(t *testing.T) {
	WithTestDB(t)

	InsertTestUser(t, "user-123")

	d := db.GetDB()
	var username string
	err := d.QueryRow("SELECT username FROM users WHERE id = ?", "user-123").Scan(&username)
	require.NoError(t, err)
	assert.Equal(t, "user_user-123", username)
}

// ---------- InsertTestGroup and InsertTestGroupMembership ----------

func TestInsertTestGroupAndMembership(t *testing.T) {
	WithTestDB(t)

	InsertTestUser(t, "guser-1")
	InsertTestGroup(t, "grp-1", "Admins")
	InsertTestGroupMembership(t, "guser-1", "grp-1")

	d := db.GetDB()
	var count int
	err := d.QueryRow("SELECT COUNT(*) FROM user_groups WHERE user_id = ? AND group_id = ?", "guser-1", "grp-1").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

// ---------- SetAuthorizeSig ----------

func TestSetAuthorizeSig(t *testing.T) {
	WithConfigOverride(t, func() {
		config.Bootstrap.AuthCSRFProtectionSecretKey = "test-secret"
	})

	v := url.Values{}
	v.Set("client_id", "my-client")
	v.Set("redirect_uri", "http://localhost/callback")
	v.Set("scope", "openid")
	v.Set("state", "abc")

	SetAuthorizeSig(v)

	sig := v.Get("authorize_sig")
	assert.NotEmpty(t, sig)

	// Same params should produce same sig
	v2 := url.Values{}
	v2.Set("client_id", "my-client")
	v2.Set("redirect_uri", "http://localhost/callback")
	v2.Set("scope", "openid")
	v2.Set("state", "abc")
	SetAuthorizeSig(v2)
	assert.Equal(t, sig, v2.Get("authorize_sig"))

	// Different params should produce different sig
	v3 := url.Values{}
	v3.Set("client_id", "other-client")
	v3.Set("redirect_uri", "http://localhost/callback")
	v3.Set("scope", "openid")
	v3.Set("state", "abc")
	SetAuthorizeSig(v3)
	assert.NotEqual(t, sig, v3.Get("authorize_sig"))
}

// ---------- SignedURL ----------

func TestSignedURL(t *testing.T) {
	WithConfigOverride(t, func() {
		config.Bootstrap.AuthCSRFProtectionSecretKey = "test-secret"
	})

	raw := "http://localhost/passkey/login/begin?client_id=c1&redirect_uri=http://localhost/cb&scope=openid&state=s1"
	signed := SignedURL(raw)

	u, err := url.Parse(signed)
	require.NoError(t, err)
	assert.NotEmpty(t, u.Query().Get("authorize_sig"))
	assert.Equal(t, "c1", u.Query().Get("client_id"))
}

// ---------- InsertTestClient redirect URIs JSON ----------

func TestInsertTestClient_MultipleRedirectURIs(t *testing.T) {
	WithTestDB(t)

	uris := []string{"http://localhost/cb1", "http://localhost/cb2"}
	InsertTestClient(t, "multi-uri-client", uris)

	d := db.GetDB()
	var rawURIs string
	err := d.QueryRow("SELECT redirect_uris FROM clients WHERE client_id = ?", "multi-uri-client").Scan(&rawURIs)
	require.NoError(t, err)

	var parsed []string
	err = json.Unmarshal([]byte(rawURIs), &parsed)
	require.NoError(t, err)
	assert.Equal(t, uris, parsed)
}
