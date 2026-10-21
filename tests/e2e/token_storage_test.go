package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/token"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func credentialDigest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func introspectActive(t *testing.T, ts *TestServer, raw string) bool {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.BaseURL+"/oauth2/introspect", strings.NewReader(url.Values{"token": {raw}}.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("e2e-confidential", "e2e-secret")
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result struct {
		Active bool `json:"active"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result.Active
}

func TestTokenStorageHashesAreNotCredentials(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "storage@example.com", "password123", "storage@example.com")
	issued := obtainTokensViaConfidentialClient(t, ts, "storage@example.com", "password123")
	accessHash, refreshHash := credentialDigest(issued.AccessToken), credentialDigest(issued.RefreshToken)
	for _, table := range []string{"tokens", "sessions"} {
		var storedAccess, storedRefresh string
		require.NoError(t, db.GetDB().QueryRow("SELECT access_token_hash,refresh_token_hash FROM "+table+" WHERE access_token_hash=?", accessHash).Scan(&storedAccess, &storedRefresh))
		require.Equal(t, accessHash, storedAccess)
		require.Equal(t, refreshHash, storedRefresh)
	}
	var clientID, acr string
	require.NoError(t, db.GetDB().QueryRow("SELECT client_id,acr FROM tokens WHERE access_token_hash=?", accessHash).Scan(&clientID, &acr))
	require.Equal(t, "e2e-confidential", clientID)
	require.Equal(t, "1", acr)
	require.True(t, introspectActive(t, ts, issued.AccessToken))
	require.True(t, introspectActive(t, ts, issued.RefreshToken))
	for _, stored := range []string{accessHash, refreshHash} {
		require.False(t, introspectActive(t, ts, stored), "a database hash must not authenticate an introspection request")
		req, err := http.NewRequest(http.MethodGet, ts.BaseURL+"/oauth2/userinfo", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+stored)
		resp, err := ts.Client.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
		resp, err = ts.Client.PostForm(ts.BaseURL+"/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"e2e-confidential"}, "client_secret": {"e2e-secret"}, "refresh_token": {stored}})
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
		req, err = http.NewRequest(http.MethodPost, ts.BaseURL+"/oauth2/revoke", strings.NewReader(url.Values{"token": {stored}}.Encode()))
		require.NoError(t, err)
		req.SetBasicAuth("e2e-confidential", "e2e-secret")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err = ts.Client.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
	}
	require.True(t, introspectActive(t, ts, issued.AccessToken), "presenting a hash must not revoke the real token")
	require.True(t, introspectActive(t, ts, issued.RefreshToken))
}

func TestRefreshUsesStoredMFAContext(t *testing.T) {
	ts := startTestServer(t)
	usr := createTestUser(t, "mfa-storage@example.com", "password123", "mfa-storage@example.com")
	seed := "JBSWY3DPEHPK3PXP"
	err := user.SaveTotpSecret(usr.ID, seed)
	require.NoError(t, err)
	code, err := totp.GenerateCode(seed, time.Now())
	require.NoError(t, err)
	form := url.Values{"grant_type": {"password"}, "client_id": {"e2e-confidential"}, "client_secret": {"e2e-secret"}, "username": {"mfa-storage@example.com"}, "password": {"password123"}, "totp_code": {code}}
	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", form)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var issued token.TokenResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&issued))
	require.NoError(t, resp.Body.Close())
	accessHash := credentialDigest(issued.AccessToken)
	var acr string
	require.NoError(t, db.GetDB().QueryRow("SELECT acr FROM tokens WHERE access_token_hash=?", accessHash).Scan(&acr))
	require.Equal(t, "2", acr)
	// Refresh cannot decode the old access JWT: only its hash remains. It must
	// honor the persisted authentication context, including after access expiry.
	_, err = db.GetDB().Exec(`UPDATE tokens SET access_token_expires_at=? WHERE access_token_hash=?`, time.Now().Add(-time.Hour), accessHash)
	require.NoError(t, err)
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {"e2e-confidential"}, "client_secret": {"e2e-secret"}, "refresh_token": {issued.RefreshToken}}
	resp, err = ts.Client.PostForm(ts.BaseURL+"/oauth2/token", refresh)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var rotated token.TokenResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&rotated))
	require.NoError(t, resp.Body.Close())
	require.NotEqual(t, issued.RefreshToken, rotated.RefreshToken)
	_, err = db.GetDB().Exec(`UPDATE tokens SET acr='1' WHERE access_token_hash=?`, credentialDigest(rotated.AccessToken))
	require.NoError(t, err)
	refresh.Set("refresh_token", rotated.RefreshToken)
	resp, err = ts.Client.PostForm(ts.BaseURL+"/oauth2/token", refresh)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
}

func TestRefreshRequiresStoredRecord(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "missing-storage@example.com", "password123", "missing-storage@example.com")
	issued := obtainTokensViaConfidentialClient(t, ts, "missing-storage@example.com", "password123")
	_, err := db.GetDB().Exec(`DELETE FROM tokens WHERE access_token_hash=?`, credentialDigest(issued.AccessToken))
	require.NoError(t, err)
	resp, err := ts.Client.PostForm(ts.BaseURL+"/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"e2e-confidential"}, "client_secret": {"e2e-secret"}, "refresh_token": {issued.RefreshToken}})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var count int
	require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM tokens").Scan(&count))
	require.Zero(t, count)
}
