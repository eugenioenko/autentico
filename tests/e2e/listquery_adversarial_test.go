package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func doAdminGet(t *testing.T, ts *TestServer, token, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest("GET", ts.BaseURL+path, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

func assertValidListResponse(t *testing.T, status int, body []byte) {
	t.Helper()
	assert.True(t, status >= 200 && status < 500,
		"expected non-5xx status, got %d: %s", status, string(body))
	if status == 200 {
		var parsed map[string]interface{}
		err := json.Unmarshal(body, &parsed)
		assert.NoError(t, err, "response must be valid JSON: %s", string(body))
	}
}

func TestListEndpoints_MaliciousQueryParams(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "lqadmin", "password123", "lqadmin@test.com")
	createTestUser(t, "lquser1", "password123", "lquser1@test.com")

	endpoints := []string{
		"/admin/api/users",
		"/admin/api/clients",
		"/admin/api/groups",
		"/admin/api/sessions",
		"/admin/api/deletion-requests",
	}

	maliciousQueries := []struct {
		name  string
		query string
	}{
		// Sort allowlist enforcement (our code, not stdlib)
		{"sqli_sort_drop", "sort=name;DROP+TABLE+users;--"},
		{"sqli_sort_union", "sort=name+UNION+SELECT+*+FROM+users--"},

		// Order binary enforcement (our code)
		{"sqli_order_drop", "order=ASC;DROP+TABLE+users;--"},

		// Limit/offset clamping (our code)
		{"int_overflow_limit", "limit=99999999999999999999999"},
		{"negative_limit", "limit=-999999"},
		{"negative_offset", "offset=-999999"},
		{"limit_zero", "limit=0"},

		// Long search truncation (our MaxSearchLength code)
		{"long_search", "search=" + strings.Repeat("A", api.MaxSearchLength+1)},

		// Filter allowlist enforcement (our code)
		{"sqli_filter_unknown", "password=secret&admin=true"},

		// Combined attack exercising all our validation layers at once
		{"combined_all", "sort=name;DROP--&order=ASC;--&search='+OR+1%3D1&limit=-1&offset=-1&role=admin'+OR+'1'%3D'1"},

		// Empty params (our defaults kick in)
		{"empty_all", "sort=&order=&search=&limit=&offset="},
	}

	for _, ep := range endpoints {
		for _, mq := range maliciousQueries {
			t.Run(ep+"_"+mq.name, func(t *testing.T) {
				status, body := doAdminGet(t, ts, adminToken, ep+"?"+mq.query)
				assertValidListResponse(t, status, body)
			})
		}
	}
}

func TestListEndpoints_NoAuth_Rejected(t *testing.T) {
	ts := startTestServer(t)

	endpoints := []string{
		"/admin/api/users",
		"/admin/api/clients",
		"/admin/api/groups",
		"/admin/api/sessions",
		"/admin/api/deletion-requests",
	}

	for _, ep := range endpoints {
		t.Run(ep+"_no_token", func(t *testing.T) {
			status, _ := doAdminGet(t, ts, "", ep+"?sort=name'+OR+'1'%3D'1--")
			assert.Equal(t, http.StatusUnauthorized, status)
		})

		t.Run(ep+"_garbage_token", func(t *testing.T) {
			status, _ := doAdminGet(t, ts, "not-a-valid-jwt-token", ep+"?search='+OR+1%3D1--")
			assert.Equal(t, http.StatusUnauthorized, status)
		})

		t.Run(ep+"_sqli_in_bearer", func(t *testing.T) {
			status, _ := doAdminGet(t, ts, "' OR 1=1--", ep)
			assert.Equal(t, http.StatusUnauthorized, status)
		})
	}
}

func TestListEndpoints_NonAdminUser_Rejected(t *testing.T) {
	ts := startTestServer(t)
	createTestUser(t, "normaluser", "password123", "normal@test.com")
	tokenResp := obtainTokensViaPasswordGrant(t, ts, "normaluser", "password123")

	endpoints := []string{
		"/admin/api/users",
		"/admin/api/clients",
		"/admin/api/groups",
		"/admin/api/sessions",
		"/admin/api/deletion-requests",
	}

	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			status, _ := doAdminGet(t, ts, tokenResp.AccessToken, ep+"?sort=name;DROP+TABLE+users;--")
			assert.True(t, status == http.StatusUnauthorized || status == http.StatusForbidden,
				"non-admin must be rejected, got %d", status)
		})
	}
}

func TestListEndpoints_ResponseStructure(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "structadmin", "password123", "structadmin@test.com")

	for i := 0; i < 5; i++ {
		createTestUser(t, "paguser"+string(rune('0'+i)), "password123", "paguser"+string(rune('0'+i))+"@test.com")
	}

	t.Run("pagination_limit_respected", func(t *testing.T) {
		status, body := doAdminGet(t, ts, adminToken, "/admin/api/users?limit=2&offset=0")
		require.Equal(t, http.StatusOK, status)

		var resp struct {
			Data struct {
				Items []json.RawMessage `json:"items"`
				Total int              `json:"total"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(body, &resp))
		assert.LessOrEqual(t, len(resp.Data.Items), 2)
		assert.GreaterOrEqual(t, resp.Data.Total, 5)
	})

	t.Run("negative_limit_uses_default", func(t *testing.T) {
		status, body := doAdminGet(t, ts, adminToken, "/admin/api/users?limit=-1")
		require.Equal(t, http.StatusOK, status)

		var resp struct {
			Data struct {
				Items []json.RawMessage `json:"items"`
				Total int              `json:"total"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(body, &resp))
		assert.Greater(t, len(resp.Data.Items), 0, "default limit should return items")
	})

	t.Run("huge_offset_returns_empty", func(t *testing.T) {
		status, body := doAdminGet(t, ts, adminToken, "/admin/api/users?offset=999999")
		require.Equal(t, http.StatusOK, status)

		var resp struct {
			Data struct {
				Items []json.RawMessage `json:"items"`
				Total int              `json:"total"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(body, &resp))
		assert.Empty(t, resp.Data.Items)
		assert.GreaterOrEqual(t, resp.Data.Total, 5)
	})
}

// --- LIKE wildcard abuse against real DB ---

func TestListEndpoints_LIKEWildcardAbuse(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "wladmin", "password123", "wladmin@test.com")
	createTestUser(t, "wluser", "password123", "wluser@test.com")

	wildcards := []struct {
		name   string
		search string
	}{
		{"percent_only", "%"},
		{"underscore_only", "_"},
		{"double_percent", "%%"},
		{"wildcard_chain", "%a%b%c%d%e%f%"},
		{"underscore_chain", "________"},
		{"mixed_wildcards", "%__%_%__%"},
		{"glob_star", "*"},
		{"glob_question", "?"},
		{"bracket_glob", "[a-z]"},
	}

	for _, wc := range wildcards {
		t.Run(wc.name, func(t *testing.T) {
			status, body := doAdminGet(t, ts, adminToken,
				"/admin/api/users?search="+url.QueryEscape(wc.search))
			assertValidListResponse(t, status, body)
		})
	}
}

// --- 2. Error message information disclosure ---

func TestListEndpoints_ErrorResponseNoInfoLeak(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "leakadmin", "password123", "leakadmin@test.com")

	sensitivePatterns := []string{
		"SQL", "sqlite", "syntax error", "no such table",
		"no such column", "LIKE or GLOB",
		"/home/", "/tmp/", "/var/", ".go:", "goroutine",
		"runtime error", "panic", "stack trace",
	}

	probes := []struct {
		name  string
		query string
	}{
		{"long_search", "search=" + strings.Repeat("x", 199)},
		{"unicode_search", "search=" + url.QueryEscape(strings.Repeat("🎯", 40))},
		{"special_chars", "search=" + url.QueryEscape("'\"\\%_[];--")},
		{"invalid_date_from", "created_at_from=" + url.QueryEscape("not-a-date'; DROP TABLE")},
		{"invalid_date_to", "created_at_to=" + url.QueryEscape("ZZZZZZZZZZZZZZZ")},
	}

	endpoints := []string{
		"/admin/api/users",
		"/admin/api/clients",
		"/admin/api/groups",
	}

	for _, ep := range endpoints {
		for _, p := range probes {
			t.Run(ep+"_"+p.name, func(t *testing.T) {
				status, body := doAdminGet(t, ts, adminToken, ep+"?"+p.query)
				if status >= 400 {
					bodyStr := string(body)
					for _, pat := range sensitivePatterns {
						assert.NotContains(t, strings.ToLower(bodyStr), strings.ToLower(pat),
							"error response must not leak internal detail: found %q in %s", pat, bodyStr)
					}
				}
			})
		}
	}
}

// --- Group filter bypass path ---

func TestListEndpoints_GroupFilterBypass(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "grpfiltadmin", "password123", "grpfiltadmin@test.com")
	createTestUser(t, "grpfiltuser", "password123", "grpfiltuser@test.com")

	payloads := []struct {
		name  string
		group string
	}{
		{"sqli_or", "' OR '1'='1"},
		{"sqli_union", "x' UNION SELECT * FROM users--"},
		{"sqli_drop", "x'; DROP TABLE users;--"},
		{"sqli_subquery", "x' AND 1=(SELECT COUNT(*) FROM users)--"},
		{"empty", ""},
		{"long_value", strings.Repeat("G", api.MaxSearchLength+1)},
		{"null_byte", "group\x00injected"},
		{"wildcard", "%"},
	}

	for _, p := range payloads {
		t.Run(p.name, func(t *testing.T) {
			status, body := doAdminGet(t, ts, adminToken,
				"/admin/api/users?group="+url.QueryEscape(p.group))
			assertValidListResponse(t, status, body)
		})
	}
}

// --- 6. user_id raw query param on /admin/api/sessions ---

func TestListEndpoints_SessionsUserIDInjection(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "sessadmin", "password123", "sessadmin@test.com")

	payloads := []struct {
		name   string
		userID string
	}{
		{"sqli_or", "' OR '1'='1"},
		{"sqli_union", "x' UNION SELECT * FROM tokens--"},
		{"sqli_drop", "'; DROP TABLE sessions;--"},
		{"sqli_subquery", "' AND 1=(SELECT COUNT(*) FROM users)--"},
		{"long_id", strings.Repeat("A", api.MaxSearchLength+1)},
		{"null_byte", "user\x00id"},
		{"empty", ""},
		{"wildcard", "%"},
		{"uuid_format", "00000000-0000-0000-0000-000000000000"},
	}

	for _, p := range payloads {
		t.Run(p.name, func(t *testing.T) {
			status, body := doAdminGet(t, ts, adminToken,
				"/admin/api/sessions?user_id="+url.QueryEscape(p.userID))
			assertValidListResponse(t, status, body)
		})
	}
}

// --- 7. Date range semantic abuse against real DB ---

func TestListEndpoints_DateRangeSemanticAbuse(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "dateadmin", "password123", "dateadmin@test.com")
	createTestUser(t, "dateuser", "password123", "dateuser@test.com")

	queries := []struct {
		name  string
		query string
	}{
		{"inverted_range", "created_at_from=2099-12-31&created_at_to=2000-01-01"},
		{"non_date_string", "created_at_from=ZZZZZ&created_at_to=not-a-date"},
		{"epoch_zero", "created_at_from=0000-00-00&created_at_to=0000-00-00"},
		{"far_future", "created_at_from=9999-99-99"},
		{"negative_value", "created_at_from=-1&created_at_to=-99999"},
		{"unix_timestamp", "created_at_from=1700000000"},
		{"iso_with_tz", "created_at_from=" + url.QueryEscape("2024-01-01T00:00:00+05:00")},
		{"only_to_future", "created_at_to=9999-12-31"},
		{"only_from_past", "created_at_from=1970-01-01"},
	}

	for _, q := range queries {
		t.Run(q.name, func(t *testing.T) {
			status, body := doAdminGet(t, ts, adminToken, "/admin/api/users?"+q.query)
			assertValidListResponse(t, status, body)
		})
	}
}

