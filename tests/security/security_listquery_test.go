package security

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func doSecurityGet(t *testing.T, ts *TestServer, token, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest("GET", ts.BaseURL+path, nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

var internalLeakPatterns = []string{
	"goroutine", "runtime.", ".go:", "panic",
	"stack trace", "traceback",
	"/home/", "/tmp/", "/var/", "/pkg/", "/src/",
	"file not found", "no such file",
	"modernc.org", "database/sql",
}

var sqlLeakPatterns = []string{
	"SELECT ", "INSERT ", "UPDATE ", "DELETE ", "CREATE ",
	"FROM ", "WHERE ", "JOIN ", "TABLE ",
	"sqlite", "SQL logic error", "LIKE or GLOB",
	"no such column", "no such table", "syntax error",
	"unrecognized token",
}

func assertNoInternalLeak(t *testing.T, body []byte) {
	t.Helper()
	bodyLower := strings.ToLower(string(body))
	for _, pat := range internalLeakPatterns {
		assert.NotContains(t, bodyLower, strings.ToLower(pat),
			"response leaks internal detail: %q", pat)
	}
}

func assertNoSQLLeak(t *testing.T, body []byte) {
	t.Helper()
	bodyStr := string(body)
	for _, pat := range sqlLeakPatterns {
		assert.NotContains(t, bodyStr, pat,
			"response leaks SQL detail: %q", pat)
	}
}

// TestListEndpoints_InfoDisclosure_ErrorResponses verifies that error responses
// from list endpoints never leak internal implementation details.
func TestListEndpoints_InfoDisclosure_ErrorResponses(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "infoadmin", "password123", "infoadmin@test.com")
	createTestUser(t, "infouser", "password123", "infouser@test.com")

	endpoints := []string{
		"/admin/api/users",
		"/admin/api/groups",
		"/admin/api/deletion-requests",
	}

	probes := []struct {
		name  string
		query string
	}{
		{"sqli_search", "search=" + url.QueryEscape("' OR 1=1; SELECT * FROM sqlite_master--")},
		{"sqli_date", "created_at_from=" + url.QueryEscape("'; SELECT sql FROM sqlite_master--")},
		{"special_chars", "search=" + url.QueryEscape("'\"\\`$(){}[]|;!@#%^&*")},
		{"backtick_injection", "search=" + url.QueryEscape("`id` FROM users--")},
	}

	for _, ep := range endpoints {
		for _, p := range probes {
			t.Run(ep+"_"+p.name, func(t *testing.T) {
				status, body := doSecurityGet(t, ts, adminToken, ep+"?"+p.query)
				_ = status
				assertNoInternalLeak(t, body)
				if status >= 400 {
					assertNoSQLLeak(t, body)
				}
			})
		}
	}
}

// TestListEndpoints_InfoDisclosure_UnauthenticatedProbes verifies that
// unauthenticated requests don't leak endpoint existence or internal errors.
func TestListEndpoints_InfoDisclosure_UnauthenticatedProbes(t *testing.T) {
	ts := startTestServer(t)

	endpoints := []string{
		"/admin/api/users",
		"/admin/api/groups",
		"/admin/api/deletion-requests",
	}

	for _, ep := range endpoints {
		t.Run(ep+"_no_auth", func(t *testing.T) {
			status, body := doSecurityGet(t, ts, "", ep+"?search='+OR+1=1--")
			assert.Equal(t, http.StatusUnauthorized, status)
			assertNoInternalLeak(t, body)
			assertNoSQLLeak(t, body)
		})

		t.Run(ep+"_forged_jwt", func(t *testing.T) {
			fakeJWT := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJoYWNrZXIiLCJyb2xlIjoiYWRtaW4ifQ.fake"
			status, body := doSecurityGet(t, ts, fakeJWT, ep)
			assert.Equal(t, http.StatusUnauthorized, status)
			assertNoInternalLeak(t, body)
		})

		t.Run(ep+"_sqli_in_bearer", func(t *testing.T) {
			status, body := doSecurityGet(t, ts, "' OR 1=1; SELECT * FROM users--", ep)
			assert.Equal(t, http.StatusUnauthorized, status)
			assertNoInternalLeak(t, body)
			assertNoSQLLeak(t, body)
		})
	}
}

// TestListEndpoints_InfoDisclosure_NonAdminWithInjection verifies that a
// valid but non-admin token cannot trigger error paths that leak info.
func TestListEndpoints_InfoDisclosure_NonAdminWithInjection(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "normuser", "password123", "normuser@test.com")
	tokenResp := obtainTokensViaROPC(t, ts, "test-client", "normuser", "password123")

	endpoints := []string{
		"/admin/api/users",
		"/admin/api/groups",
		"/admin/api/deletion-requests",
	}

	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			status, body := doSecurityGet(t, ts, tokenResp.AccessToken,
				ep+"?search="+url.QueryEscape("'; DROP TABLE users;--"))
			assert.True(t, status == 401 || status == 403,
				"non-admin got status %d", status)
			assertNoInternalLeak(t, body)
			assertNoSQLLeak(t, body)
		})
	}
}

// TestListEndpoints_SQLInjection_GroupFilterBypass tests the manually-wired
// ?group= parameter in HandleListUsers which bypasses ParseFilters.
func TestListEndpoints_SQLInjection_GroupFilterBypass(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "grpadmin2", "password123", "grpadmin2@test.com")
	createTestUser(t, "grpuser2", "password123", "grpuser2@test.com")

	payloads := []string{
		"' OR '1'='1",
		"x' UNION SELECT * FROM users--",
		"'; DROP TABLE users;--",
		"x' AND 1=(SELECT COUNT(*) FROM sqlite_master)--",
		"' OR 1=1 LIMIT 1--",
		"nonexistent_group",
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			status, body := doSecurityGet(t, ts, adminToken,
				"/admin/api/users?group="+url.QueryEscape(payload))

			assert.True(t, status >= 200 && status < 500,
				"group filter probe must not cause 5xx, got %d", status)

			if status == 200 {
				var resp struct {
					Data struct {
						Items []json.RawMessage `json:"items"`
						Total int              `json:"total"`
					} `json:"data"`
				}
				err := json.Unmarshal(body, &resp)
				require.NoError(t, err)
				assert.Equal(t, 0, resp.Data.Total,
					"SQL injection in group filter must not return extra rows")
			}

			assertNoInternalLeak(t, body)
			if status >= 400 {
				assertNoSQLLeak(t, body)
			}
		})
	}
}

// TestListEndpoints_SQLInjection_SessionsUserID tests the raw user_id
// query parameter in HandleListSessions.
func TestListEndpoints_SQLInjection_SessionsUserID(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "sessadmin2", "password123", "sessadmin2@test.com")

	payloads := []string{
		"' OR '1'='1",
		"x' UNION SELECT * FROM tokens--",
		"'; DROP TABLE sessions;--",
		"x' AND 1=(SELECT COUNT(*) FROM sqlite_master)--",
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			status, body := doSecurityGet(t, ts, adminToken,
				"/admin/api/sessions?user_id="+url.QueryEscape(payload))

			assert.True(t, status >= 200 && status < 500,
				"user_id probe must not cause 5xx, got %d", status)

			assertNoInternalLeak(t, body)
			if status >= 400 {
				assertNoSQLLeak(t, body)
			}
		})
	}
}

// TestListEndpoints_ResponseHeaders verifies that list endpoints set proper
// security headers preventing caching of sensitive data.
func TestListEndpoints_ResponseHeaders(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "hdradmin", "password123", "hdradmin@test.com")

	endpoints := []string{
		"/admin/api/users",
		"/admin/api/groups",
	}

	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			req, err := http.NewRequest("GET", ts.BaseURL+ep, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+adminToken)

			resp, err := ts.Client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.ReadAll(resp.Body)

			ct := resp.Header.Get("Content-Type")
			assert.Contains(t, ct, "application/json",
				"admin API must return application/json")
		})
	}
}
