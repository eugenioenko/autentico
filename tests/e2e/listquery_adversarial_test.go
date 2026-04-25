package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

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
		// SQL injection in sort
		{"sqli_sort_drop", "sort=name;DROP+TABLE+users;--"},
		{"sqli_sort_union", "sort=name+UNION+SELECT+*+FROM+users--"},
		{"sqli_sort_quote", "sort=name'+OR+'1'%3D'1"},
		{"sqli_sort_comment", "sort=name/**/UNION/**/SELECT/**/1"},

		// SQL injection in order
		{"sqli_order_drop", "order=ASC;DROP+TABLE+users;--"},
		{"sqli_order_subquery", "order=DESC,(SELECT+password+FROM+users)"},

		// SQL injection in search
		{"sqli_search_classic", "search='+OR+1%3D1--"},
		{"sqli_search_drop", "search=';DROP+TABLE+users;--"},
		{"sqli_search_union", "search=%25'+UNION+SELECT+password+FROM+users--"},
		{"sqli_search_stacked", "search=test';+INSERT+INTO+users(username)+VALUES('pwned');--"},

		// SQL injection in filters
		{"sqli_filter_value", "role=admin'+OR+'1'%3D'1"},
		{"sqli_filter_unknown", "password=secret&admin=true"},

		// SQL injection in date ranges
		{"sqli_date_from", "created_at_from=2024-01-01'+OR+'1'%3D'1"},
		{"sqli_date_drop", "created_at_to=2024-01-01;DROP+TABLE+users;--"},

		// Integer overflow in limit/offset
		{"int_overflow_limit", "limit=99999999999999999999999"},
		{"int_overflow_offset", "offset=99999999999999999999999"},
		{"negative_limit", "limit=-999999"},
		{"negative_offset", "offset=-999999"},
		{"limit_maxint64", "limit=9223372036854775807"},
		{"offset_maxint64", "offset=9223372036854775807"},
		{"limit_zero", "limit=0"},
		{"limit_float", "limit=1.5"},
		{"limit_scientific", "limit=1e10"},
		{"limit_hex", "limit=0xFF"},
		{"limit_nan", "limit=NaN"},
		{"limit_infinity", "limit=Infinity"},

		// Type confusion
		{"type_array_limit", "limit[]=1&limit[]=2"},
		{"type_object_limit", "limit[key]=1"},
		{"type_array_sort", "sort[]=name&sort[]=email"},

		// Null bytes and control characters
		{"null_byte_search", "search=test%00injected"},
		{"null_byte_sort", "sort=name%00DROP"},
		{"newline_search", "search=test%0D%0Ainjected"},
		{"tab_search", "search=test%09injected"},

		// Very long strings
		{"long_search", "search=" + strings.Repeat("A", 50000)},
		{"long_sort", "sort=" + strings.Repeat("x", 10000)},
		{"long_filter", "role=" + strings.Repeat("B", 50000)},

		// Unicode / encoding attacks
		{"unicode_search", "search=%E2%80%AE%E2%80%AEinjected"},
		{"emoji_search", "search=" + url.QueryEscape(strings.Repeat("\U0001F4A9", 1000))},
		{"zero_width_search", "search=test%E2%80%8B%E2%80%8C%E2%80%8Dinjected"},

		// HTTP parameter pollution
		{"hpp_sort", "sort=name&sort=email&sort=DROP+TABLE"},
		{"hpp_limit", "limit=10&limit=999999"},
		{"hpp_search", "search=safe&search='+OR+1%3D1--"},

		// Path traversal in filter values
		{"path_traversal_filter", "role=../../etc/passwd"},

		// Combined attacks
		{"combined_all", "sort=name;DROP--&order=ASC;--&search='+OR+1%3D1&limit=-1&offset=-1&role=admin'+OR+'1'%3D'1"},

		// Empty and whitespace
		{"empty_all", "sort=&order=&search=&limit=&offset="},
		{"whitespace_all", "sort=%20&order=%20&search=%20&limit=%20&offset=%20"},
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

// doAdminRequest sends an arbitrary-method request to the admin API.
func doAdminRequest(t *testing.T, ts *TestServer, method, token, path string, body io.Reader) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, ts.BaseURL+path, body)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, respBody
}

// --- 1. LIKE wildcard abuse against real DB ---

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

// --- 3. HTTP method confusion ---

func TestListEndpoints_HTTPMethodConfusion(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "methodadmin", "password123", "methodadmin@test.com")

	endpoints := []string{
		"/admin/api/users",
		"/admin/api/clients",
		"/admin/api/groups",
	}

	methods := []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

	for _, ep := range endpoints {
		for _, method := range methods {
			t.Run(ep+"_"+method, func(t *testing.T) {
				var body io.Reader
				if method == "POST" || method == "PUT" || method == "PATCH" {
					body = strings.NewReader(`{"search":"' OR 1=1--"}`)
				}
				status, _ := doAdminRequest(t, ts, method, adminToken, ep+"?sort=name;DROP+TABLE+users;--", body)
				assert.NotEqual(t, http.StatusOK, status,
					"%s to GET-only list endpoint should not return 200", method)
			})
		}
	}
}

// --- 4. Double URL encoding ---

func TestListEndpoints_DoubleURLEncoding(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "dencadmin", "password123", "dencadmin@test.com")

	queries := []struct {
		name  string
		query string
	}{
		{"double_encoded_quote", "search=%2527+OR+1%253D1--"},
		{"double_encoded_semicolon", "sort=name%253BDROP+TABLE"},
		{"double_encoded_null", "search=%2500injected"},
		{"double_encoded_crlf", "search=%250D%250Ainjected"},
		{"triple_encoded", "search=%25252527"},
	}

	for _, q := range queries {
		t.Run(q.name, func(t *testing.T) {
			status, body := doAdminGet(t, ts, adminToken, "/admin/api/users?"+q.query)
			assertValidListResponse(t, status, body)
		})
	}
}

// --- 5. Group filter bypass path ---

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
		{"long_value", strings.Repeat("G", 10000)},
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
		{"long_id", strings.Repeat("A", 50000)},
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

// --- 8. Response body content validation on errors ---

func TestListEndpoints_500ResponseNoInternalDetails(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "err500admin", "password123", "err500admin@test.com")

	forbidden := []string{
		"goroutine", "runtime.", ".go:", "panic",
		"stack", "SELECT ", "FROM ", "WHERE ",
		"INSERT ", "DELETE ", "UPDATE ", "CREATE ",
		"/home/", "/tmp/", "/var/", "/pkg/",
	}

	probes := []string{
		"/admin/api/users?search=" + url.QueryEscape(strings.Repeat("%_", 99)),
		"/admin/api/users?created_at_from=" + url.QueryEscape("'; DROP TABLE users;--"),
		"/admin/api/clients?search=" + url.QueryEscape("' UNION SELECT 1--"),
		"/admin/api/groups?sort=" + url.QueryEscape("id; DROP TABLE groups;--"),
	}

	for _, probe := range probes {
		t.Run(probe, func(t *testing.T) {
			status, body := doAdminGet(t, ts, adminToken, probe)
			if status >= 500 {
				bodyStr := string(body)
				for _, pat := range forbidden {
					assert.NotContains(t, bodyStr, pat,
						"500 response must not contain %q", pat)
				}
			}
		})
	}
}

// --- 9. Concurrent request flooding ---

func TestListEndpoints_ConcurrentRequests(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "concadmin", "password123", "concadmin@test.com")
	for i := 0; i < 10; i++ {
		createTestUser(t, fmt.Sprintf("concuser%d", i), "password123", fmt.Sprintf("concuser%d@test.com", i))
	}

	queries := []string{
		"/admin/api/users?search=" + url.QueryEscape("' OR 1=1--"),
		"/admin/api/users?limit=-1&offset=-1",
		"/admin/api/users?sort=name;DROP+TABLE+users;--",
		"/admin/api/users?group=" + url.QueryEscape("' OR '1'='1"),
		"/admin/api/clients?search=%25",
		"/admin/api/groups?limit=999999",
		"/admin/api/users?created_at_from=ZZZZZ",
		"/admin/api/sessions?user_id=" + url.QueryEscape("' OR 1=1--"),
		"/admin/api/users?search=normal",
		"/admin/api/users?limit=2&offset=0",
	}

	const concurrency = 20
	var wg sync.WaitGroup
	errors := make(chan string, concurrency*len(queries))

	for i := 0; i < concurrency; i++ {
		for _, q := range queries {
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				req, err := http.NewRequest("GET", ts.BaseURL+path, nil)
				if err != nil {
					errors <- fmt.Sprintf("request creation failed: %v", err)
					return
				}
				req.Header.Set("Authorization", "Bearer "+adminToken)
				resp, err := ts.Client.Do(req)
				if err != nil {
					errors <- fmt.Sprintf("request failed: %v", err)
					return
				}
				defer func() { _ = resp.Body.Close() }()
				_, _ = io.ReadAll(resp.Body)
				if resp.StatusCode >= 500 {
					errors <- fmt.Sprintf("500 on %s: status=%d", path, resp.StatusCode)
				}
			}(q)
		}
	}

	wg.Wait()
	close(errors)

	var errs []string
	for e := range errors {
		errs = append(errs, e)
	}
	assert.Empty(t, errs, "concurrent requests should not cause 500s or panics: %v", errs)
}

// --- 10. Content-Type header manipulation ---

func TestListEndpoints_ContentTypeManipulation(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "ctadmin", "password123", "ctadmin@test.com")

	contentTypes := []string{
		"application/xml",
		"text/html",
		"multipart/form-data",
		"application/x-www-form-urlencoded",
		"text/plain",
		"application/octet-stream",
		"",
	}

	for _, ct := range contentTypes {
		t.Run(ct, func(t *testing.T) {
			req, err := http.NewRequest("GET", ts.BaseURL+"/admin/api/users?search=test", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+adminToken)
			if ct != "" {
				req.Header.Set("Content-Type", ct)
			}
			resp, err := ts.Client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			assert.Equal(t, http.StatusOK, resp.StatusCode,
				"GET list endpoint should ignore Content-Type header, got %d: %s", resp.StatusCode, string(body))
		})
	}
}

// --- 11. Request body on GET endpoints ---

func TestListEndpoints_GETWithBody(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "bodyadmin", "password123", "bodyadmin@test.com")

	bodies := []struct {
		name string
		body string
	}{
		{"json_sqli", `{"sort": "name; DROP TABLE users;--", "search": "' OR 1=1--"}`},
		{"huge_body", strings.Repeat(`{"a":"b"}`, 10000)},
		{"xml_body", `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`},
		{"null_bytes", string([]byte{0x00, 0x00, 0x00})},
	}

	for _, b := range bodies {
		t.Run(b.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", ts.BaseURL+"/admin/api/users", strings.NewReader(b.body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+adminToken)
			req.Header.Set("Content-Type", "application/json")
			resp, err := ts.Client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			respBody, _ := io.ReadAll(resp.Body)
			assert.Equal(t, http.StatusOK, resp.StatusCode,
				"GET with body should be ignored and return results, got %d: %s", resp.StatusCode, string(respBody))
		})
	}
}
