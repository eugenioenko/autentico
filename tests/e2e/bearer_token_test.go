package e2e

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUserInfo_FormBodyToken verifies RFC 6750 §2.2: access_token MAY be sent
// as application/x-www-form-urlencoded body parameter on a POST request.
func TestUserInfo_FormBodyToken(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "user@test.com", "password123", "user@test.com")
	tokens := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	form := url.Values{}
	form.Set("access_token", tokens.AccessToken)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/userinfo", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "form-body token must be accepted: %s", string(body))
	assert.Contains(t, string(body), "sub")
}

// TestUserInfo_DualCredentials_Rejected verifies RFC 6750 §2.2: a request that
// passes the token in both the Authorization header and the POST body MUST be rejected.
func TestUserInfo_DualCredentials_Rejected(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "user@test.com", "password123", "user@test.com")
	tokens := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	form := url.Values{}
	form.Set("access_token", tokens.AccessToken)

	req, err := http.NewRequest("POST", ts.BaseURL+"/oauth2/userinfo", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken) // also in header

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	// RFC 6750 §2.2: MUST NOT use more than one method
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "dual credentials must be rejected: %s", string(body))
	assert.Contains(t, string(body), "invalid_request")
}

// TestUserInfo_WWWAuthenticateHeader verifies RFC 6750 §3.1: the resource server
// MUST include WWW-Authenticate on 401 responses, with the correct Bearer format.
func TestUserInfo_WWWAuthenticateHeader(t *testing.T) {
	ts := startTestServer(t)

	cases := []struct {
		name       string
		setupReq   func(*http.Request)
		wantStatus int
	}{
		{
			name:       "no token",
			setupReq:   func(r *http.Request) {},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "invalid token",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer not-a-real-token")
			},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", ts.BaseURL+"/oauth2/userinfo", nil)
			require.NoError(t, err)
			tc.setupReq(req)

			resp, err := ts.Client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.wantStatus, resp.StatusCode)
			wwwAuth := resp.Header.Get("WWW-Authenticate")
			assert.NotEmpty(t, wwwAuth, "RFC 6750 §3.1: WWW-Authenticate MUST be present on 401")
			assert.Contains(t, wwwAuth, "Bearer")
		})
	}
}

// TestUserInfo_QueryParamToken_NotAccepted verifies RFC 6750 §5.3:
// passing access_token as a URI query parameter is not recommended and MUST NOT
// be accepted by this server (no endpoint supports it).
func TestUserInfo_QueryParamToken_NotAccepted(t *testing.T) {
	ts := startTestServer(t)

	createTestUser(t, "user@test.com", "password123", "user@test.com")
	tokens := obtainTokensViaPasswordGrant(t, ts, "user@test.com", "password123")

	// Attempt to use token as query parameter — must NOT succeed
	reqURL := ts.BaseURL + "/oauth2/userinfo?access_token=" + tokens.AccessToken
	resp, err := ts.Client.Get(reqURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Without a proper Authorization header, the server should return 401
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "query param token must not be accepted")
}
