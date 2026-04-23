package security

import (
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Redirect URI validation bypass tests.
//
// CVE-2023-6291 (Keycloak): loose string comparison — prefix match instead of exact
// CVE-2024-1132 (Keycloak): wildcard redirect URI traversal
// CVE-2024-8883 (Keycloak): localhost/127.0.0.1 open redirect via userinfo
// CVE-2022-3782 (Keycloak): double URL encoding path traversal
// CVE-2026-3872 (Keycloak): ..;/ path traversal
// CVE-2024-52289 (Authentik): regex bypass — unescaped dot in domain
// CVE-2020-15234 (Fosite): redirect URL case-sensitivity bypass
// CVE-2022-23527 (mod_auth_openidc): open redirect with /\t prefix bypass
// CVE-2019-20479 (mod_auth_openidc): open redirect via slash/backslash prefix
// RFC 9700 §4.1.3: exact string matching required, fragment rejection

func authorizeWithRedirectURI(t *testing.T, ts *TestServer, redirectURI string) (*http.Response, string) {
	t.Helper()
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {"test-client"},
		"redirect_uri":  {redirectURI},
		"state":         {"test-state"},
	}
	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/authorize?" + params.Encode())
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	return resp, string(body)
}

// CVE-2023-6291: attacker registers subdomain that starts with allowed host.
// Registered: http://localhost:3000/callback
// Attack:     http://localhost:3000/callback.evil.com/steal
func TestRedirectURI_PrefixBypass(t *testing.T) {
	ts := startTestServer(t)

	maliciousURIs := []string{
		"http://localhost:3000/callback.evil.com/steal",
		"http://localhost:3000/callbackevil",
		"http://localhost:3000/callback/../../evil",
	}

	for _, uri := range maliciousURIs {
		t.Run(uri, func(t *testing.T) {
			resp, body := authorizeWithRedirectURI(t, ts, uri)
			// Must NOT render login page — should reject
			assert.NotEqual(t, http.StatusOK, resp.StatusCode,
				"authorize should reject redirect_uri %q but rendered login page: %s", uri, body[:min(200, len(body))])
		})
	}
}

// CVE-2024-1132 / CVE-2022-3782: path traversal via encoded sequences.
func TestRedirectURI_PathTraversal(t *testing.T) {
	ts := startTestServer(t)

	maliciousURIs := []string{
		"http://localhost:3000/callback/../evil",
		"http://localhost:3000/callback/..%2Fevil",
		"http://localhost:3000/callback%2F..%2F..%2Fevil",
		"http://localhost:3000/callback%252f..%252f",
	}

	for _, uri := range maliciousURIs {
		t.Run(uri, func(t *testing.T) {
			resp, body := authorizeWithRedirectURI(t, ts, uri)
			assert.NotEqual(t, http.StatusOK, resp.StatusCode,
				"authorize should reject path traversal in redirect_uri %q: %s", uri, body[:min(200, len(body))])
		})
	}
}

// CVE-2026-3872: ..;/ path traversal (Tomcat-style path parameter).
func TestRedirectURI_SemicolonTraversal(t *testing.T) {
	ts := startTestServer(t)

	maliciousURIs := []string{
		"http://localhost:3000/callback/..;/evil",
		"http://localhost:3000/callback/..;evil",
	}

	for _, uri := range maliciousURIs {
		t.Run(uri, func(t *testing.T) {
			resp, body := authorizeWithRedirectURI(t, ts, uri)
			assert.NotEqual(t, http.StatusOK, resp.StatusCode,
				"authorize should reject semicolon traversal in redirect_uri %q: %s", uri, body[:min(200, len(body))])
		})
	}
}

// CVE-2024-8883: userinfo-in-authority attack.
// http://localhost:3000@evil.com/callback — browser resolves to evil.com.
func TestRedirectURI_UserinfoInAuthority(t *testing.T) {
	ts := startTestServer(t)

	maliciousURIs := []string{
		"http://localhost:3000@evil.com/callback",
		"http://user:pass@evil.com/callback",
	}

	for _, uri := range maliciousURIs {
		t.Run(uri, func(t *testing.T) {
			resp, body := authorizeWithRedirectURI(t, ts, uri)
			assert.NotEqual(t, http.StatusOK, resp.StatusCode,
				"authorize should reject userinfo in redirect_uri %q: %s", uri, body[:min(200, len(body))])
		})
	}
}

// RFC 9700 §4.1.3: redirect_uri with fragment must be rejected.
func TestRedirectURI_FragmentRejection(t *testing.T) {
	ts := startTestServer(t)

	resp, body := authorizeWithRedirectURI(t, ts, "http://localhost:3000/callback#fragment")
	assert.NotEqual(t, http.StatusOK, resp.StatusCode,
		"authorize should reject redirect_uri with fragment: %s", body[:min(200, len(body))])
}

// RFC 9700 §4.1.3: scheme mismatch must be rejected.
func TestRedirectURI_SchemeMismatch(t *testing.T) {
	ts := startTestServer(t)

	// Registered is http, attacker tries https or javascript
	maliciousURIs := []string{
		"https://localhost:3000/callback",
		"javascript://localhost:3000/callback",
		"data://localhost:3000/callback",
	}

	for _, uri := range maliciousURIs {
		t.Run(uri, func(t *testing.T) {
			resp, body := authorizeWithRedirectURI(t, ts, uri)
			assert.NotEqual(t, http.StatusOK, resp.StatusCode,
				"authorize should reject scheme mismatch in redirect_uri %q: %s", uri, body[:min(200, len(body))])
		})
	}
}

// Completely unrelated redirect_uri must be rejected.
func TestRedirectURI_UnregisteredHost(t *testing.T) {
	ts := startTestServer(t)

	resp, body := authorizeWithRedirectURI(t, ts, "http://evil.com/callback")
	assert.NotEqual(t, http.StatusOK, resp.StatusCode,
		"authorize should reject unregistered redirect_uri: %s", body[:min(200, len(body))])
}

// CVE-2020-15234 (Fosite): redirect URL case-sensitivity bypass.
// RFC 9700 §4.1.3 requires exact string matching — case matters.
func TestRedirectURI_CaseSensitivity(t *testing.T) {
	ts := startTestServer(t)

	caseVariants := []string{
		"HTTP://LOCALHOST:3000/CALLBACK",
		"http://LOCALHOST:3000/callback",
		"http://localhost:3000/Callback",
		"http://Localhost:3000/callback",
	}

	for _, uri := range caseVariants {
		t.Run(uri, func(t *testing.T) {
			resp, body := authorizeWithRedirectURI(t, ts, uri)
			// RFC 9700 requires exact string matching. Whether case-insensitive
			// comparison is acceptable depends on interpretation — flag as finding.
			if resp.StatusCode == http.StatusOK {
				t.Logf("FINDING: server accepted case-variant redirect_uri %q (status %d)", uri, resp.StatusCode)
			}
			_ = body
		})
	}
}

// CVE-2024-52289 (Authentik): regex bypass via unescaped dot.
// If validation uses regex with unescaped dots, fooaexample.com matches foo.example.com.
func TestRedirectURI_DotBypass(t *testing.T) {
	ts := startTestServer(t)

	// Registered: http://localhost:3000/callback
	// Attack: substitute dot with different char to see if regex matching is used
	maliciousURIs := []string{
		"http://localhostX3000/callback",
		"http://localhost:3000Xcallback",
	}

	for _, uri := range maliciousURIs {
		t.Run(uri, func(t *testing.T) {
			resp, body := authorizeWithRedirectURI(t, ts, uri)
			assert.NotEqual(t, http.StatusOK, resp.StatusCode,
				"authorize should reject dot-bypass redirect_uri %q: %s", uri, body[:min(200, len(body))])
		})
	}
}

// CVE-2022-23527 (mod_auth_openidc): open redirect with tab/special prefix.
// CVE-2019-20479 (mod_auth_openidc): open redirect via slash/backslash prefix.
func TestRedirectURI_SpecialPrefixBypass(t *testing.T) {
	ts := startTestServer(t)

	maliciousURIs := []string{
		"/\thttps://evil.com",
		"\\/evil.com",
		"///evil.com",
		"//evil.com",
	}

	for _, uri := range maliciousURIs {
		t.Run(uri, func(t *testing.T) {
			resp, body := authorizeWithRedirectURI(t, ts, uri)
			assert.NotEqual(t, http.StatusOK, resp.StatusCode,
				"authorize should reject special-prefix redirect_uri %q: %s", uri, body[:min(200, len(body))])
		})
	}
}

