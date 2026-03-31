package token

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsScopeSubset covers RFC 6749 §6: refresh scope MUST NOT exceed original grant.
func TestIsScopeSubset(t *testing.T) {
	tests := []struct {
		requested string
		original  string
		wantOK    bool
	}{
		{"openid", "openid profile email", true},
		{"openid profile", "openid profile email", true},
		{"openid profile email", "openid profile email", true},
		{"openid offline_access", "openid profile email", false}, // offline_access not in original
		{"openid profile admin", "openid profile email", false},  // admin not in original
		{"", "openid profile email", true},                       // empty requested = subset
		{"openid", "", false},                                     // non-empty requested, empty original
		{"openid", "openid", true},                               // exact match
	}
	for _, tc := range tests {
		got := isScopeSubset(tc.requested, tc.original)
		if got != tc.wantOK {
			t.Errorf("isScopeSubset(%q, %q) = %v, want %v", tc.requested, tc.original, got, tc.wantOK)
		}
	}
}

// TestHandleToken_RefreshTokenGrant_ScopeExpansion_Rejected verifies that a refresh
// request asking for scope beyond the original grant is rejected per RFC 6749 §6.
func TestHandleToken_RefreshTokenGrant_ScopeExpansion_Rejected(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	require.NoError(t, err)
	insertROPCTestClient(t)

	// Obtain tokens with a limited scope
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "ropc-test-client")
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("scope", "openid")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleToken(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var tokenResp TokenResponse
	err = json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	require.NoError(t, err)
	require.NotEmpty(t, tokenResp.RefreshToken)

	// Refresh and request a broader scope — must be rejected
	form2 := url.Values{}
	form2.Add("grant_type", "refresh_token")
	form2.Add("refresh_token", tokenResp.RefreshToken)
	form2.Add("scope", "openid profile email") // more than "openid"

	req2 := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	HandleToken(rr2, req2)

	// RFC 6749 §6: MUST NOT issue scope broader than original grant
	assert.Equal(t, http.StatusBadRequest, rr2.Code, "scope expansion on refresh must be rejected")
	assert.Contains(t, rr2.Body.String(), "invalid_scope")
}

// TestHandleToken_RefreshTokenGrant_ScopeDownscope verifies that a refresh request
// can legitimately reduce the scope per RFC 6749 §6.
func TestHandleToken_RefreshTokenGrant_ScopeDownscope(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
	})

	_, err := user.CreateUser("testuser", "password123", "testuser@example.com")
	require.NoError(t, err)
	insertROPCTestClient(t)

	// Obtain tokens with a broad scope
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", "ropc-test-client")
	form.Add("username", "testuser")
	form.Add("password", "password123")
	form.Add("scope", "openid profile")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleToken(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var tokenResp TokenResponse
	err = json.Unmarshal(rr.Body.Bytes(), &tokenResp)
	require.NoError(t, err)
	require.NotEmpty(t, tokenResp.RefreshToken)

	// Refresh with a narrower scope — must succeed and return the downscoped value
	form2 := url.Values{}
	form2.Add("grant_type", "refresh_token")
	form2.Add("refresh_token", tokenResp.RefreshToken)
	form2.Add("scope", "openid") // subset of original "openid profile"

	req2 := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	HandleToken(rr2, req2)

	require.Equal(t, http.StatusOK, rr2.Code, "downscoping on refresh must succeed")
	var refreshResp TokenResponse
	err = json.Unmarshal(rr2.Body.Bytes(), &refreshResp)
	require.NoError(t, err)
	// RFC 6749 §6: returned scope must reflect the downscoped request
	assert.Equal(t, "openid", refreshResp.Scope)
}
