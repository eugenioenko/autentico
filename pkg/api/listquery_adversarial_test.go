package api

import (
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var adversarialConfig = ListConfig{
	AllowedSort:    map[string]bool{"name": true, "created_at": true},
	SearchColumns:  []string{"name", "email"},
	AllowedFilters: map[string]bool{"role": true, "status": true},
	DefaultSort:    "created_at",
	MaxLimit:       50,
	TableAlias:     "u",
}

// --- SQL injection via sort/order ---

func TestBuildListQuery_SQLInjection_Sort(t *testing.T) {
	payloads := []string{
		"name; DROP TABLE users;--",
		"name UNION SELECT * FROM users--",
		"1 OR 1=1",
		"name' OR '1'='1",
		"created_at; WAITFOR DELAY '0:0:5'--",
		"name/**/UNION/**/SELECT/**/password/**/FROM/**/users",
		"CASE WHEN (1=1) THEN name ELSE email END",
		"name` OR `1`=`1",
		"name\"; DROP TABLE users;--",
		"(SELECT password FROM users LIMIT 1)",
	}
	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			params := ListParams{Sort: payload}
			result := BuildListQuery(params, adversarialConfig)
			assert.Contains(t, result.Order, "u.created_at", "rejected sort must fall back to default")
			assert.NotContains(t, result.Order, payload)
		})
	}
}

func TestBuildListQuery_SQLInjection_Order(t *testing.T) {
	payloads := []string{
		"ASC; DROP TABLE users;--",
		"DESC, (SELECT password FROM users)",
		"ASC UNION SELECT 1,2,3--",
		"1 OR 1=1",
		"ASC\nUNION SELECT * FROM users",
		"",
		"ASCENDING",
		"desc; --",
	}
	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			params := ListParams{Sort: "name", Order: payload}
			result := BuildListQuery(params, adversarialConfig)
			assert.True(t,
				strings.Contains(result.Order, "ASC") || strings.Contains(result.Order, "DESC"),
				"order must be ASC or DESC, got: %s", result.Order)
			assert.NotContains(t, result.Order, "DROP")
			assert.NotContains(t, result.Order, "UNION")
			assert.NotContains(t, result.Order, "SELECT")
		})
	}
}

// --- SQL injection via search ---

func TestBuildListQuery_SQLInjection_Search(t *testing.T) {
	payloads := []string{
		"' OR 1=1--",
		"'; DROP TABLE users;--",
		"%' UNION SELECT password FROM users--",
		"\\",
		"' AND 1=(SELECT COUNT(*) FROM users)--",
		"test%' OR '%'='",
		"a])}; DROP TABLE users;--",
		string([]byte{0x00, 0x01, 0x02}),
	}
	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			params := ListParams{Search: payload}
			result := BuildListQuery(params, adversarialConfig)
			assert.Contains(t, result.Where, "LIKE ?", "search must use parameterized queries")
			for _, arg := range result.Args {
				s, ok := arg.(string)
				if ok {
					assert.True(t, strings.HasPrefix(s, "%") && strings.HasSuffix(s, "%"),
						"search arg must be wrapped in %%, got: %q", s)
				}
			}
		})
	}
}

// --- SQL injection via filters ---

func TestBuildListQuery_SQLInjection_Filters(t *testing.T) {
	payloads := []string{
		"admin' OR '1'='1",
		"admin'; DROP TABLE users;--",
		"admin UNION SELECT 1--",
		"admin\x00injected",
	}
	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			params := ListParams{
				Filters: map[string]string{"role": payload},
			}
			result := BuildListQuery(params, adversarialConfig)
			assert.Contains(t, result.Where, "= ?", "filters must use parameterized queries")
			assert.Contains(t, result.Args, payload, "raw value must be bound, not interpolated")
		})
	}
}

func TestBuildListQuery_DisallowedFilters(t *testing.T) {
	params := ListParams{
		Filters: map[string]string{
			"password":                  "secret",
			"1=1; --":                   "x",
			"role OR 1=1":               "x",
			"name UNION SELECT * FROM":  "x",
			"../../etc/passwd":          "x",
			"status":                    "active",
		},
	}
	result := BuildListQuery(params, adversarialConfig)
	assert.Contains(t, result.Where, "u.status = ?")
	assert.NotContains(t, result.Where, "password")
	assert.NotContains(t, result.Where, "1=1")
	assert.NotContains(t, result.Where, "UNION")
	assert.NotContains(t, result.Where, "passwd")
	assert.Len(t, result.Args, 1)
}

// --- Integer overflow / boundary ---

func TestBuildListQuery_IntOverflow_Limit(t *testing.T) {
	cases := []struct {
		name  string
		limit int
	}{
		{"max_int", math.MaxInt64},
		{"max_int32", math.MaxInt32},
		{"large", 999999999},
		{"absolute_max_plus_one", AbsoluteMaxLimit + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params := ListParams{Limit: tc.limit}
			result := BuildListQuery(params, adversarialConfig)
			assert.Contains(t, result.Order, "LIMIT 50", "limit must be capped to config max")
		})
	}
}

func TestBuildListQuery_IntOverflow_Offset(t *testing.T) {
	cases := []struct {
		name   string
		offset int
	}{
		{"max_int", math.MaxInt64},
		{"max_int32", math.MaxInt32},
		{"large", 999999999},
		{"negative_max", math.MinInt64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params := ListParams{Offset: tc.offset}
			result := BuildListQuery(params, adversarialConfig)
			assert.NotContains(t, result.Order, "OFFSET -")
		})
	}
}

// --- ParseListParams adversarial HTTP query strings ---

func TestParseListParams_IntOverflow_QueryString(t *testing.T) {
	cases := []struct {
		name  string
		query string
	}{
		{"huge_limit", "limit=99999999999999999999999"},
		{"negative_huge", "limit=-99999999999999999999999"},
		{"float", "limit=1.5&offset=2.7"},
		{"hex", "limit=0xFF&offset=0x10"},
		{"scientific", "limit=1e10&offset=1e5"},
		{"nan", "limit=NaN&offset=Infinity"},
		{"empty", "limit=&offset="},
		{"whitespace", "limit=%20&offset=%09"},
		{"null_bytes", "limit=%00&offset=%00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/items?"+tc.query, nil)
			params := ParseListParams(req)
			result := BuildListQuery(params, adversarialConfig)
			assert.NotContains(t, result.Order, "LIMIT -")
			assert.NotContains(t, result.Order, "OFFSET -")
		})
	}
}

func TestParseListParams_MaliciousSearchStrings(t *testing.T) {
	cases := []struct {
		name   string
		search string
	}{
		{"very_long", strings.Repeat("A", 100000)},
		{"at_max_length", strings.Repeat("B", MaxSearchLength)},
		{"over_max_length", strings.Repeat("C", MaxSearchLength+50)},
		{"unicode_bomb", strings.Repeat("\xef\xbf\xbd", 10000)},
		{"null_byte", "test\x00injected"},
		{"newlines", "test\r\n\r\nHTTP/1.1 200 OK\r\n"},
		{"tab_inject", "test\there"},
		{"rtl_override", "test\u202einjected"},
		{"zero_width", "test\u200b\u200c\u200dinjected"},
		{"emoji_flood", strings.Repeat("\U0001F4A9", 5000)},
		{"backslash_escape", `test\\\\\\\\\\\\\\\\\\\`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params := ListParams{Search: tc.search}
			result := BuildListQuery(params, adversarialConfig)
			assert.Contains(t, result.Where, "LIKE ?")
		})
	}
}

// --- ParseDateRange injection ---

func TestParseDateRange_SQLInjection(t *testing.T) {
	payloads := []string{
		"2024-01-01' OR '1'='1",
		"2024-01-01; DROP TABLE users;--",
		"2024-01-01 UNION SELECT * FROM users--",
		"' OR 1=1--",
		"2024-01-01\x00injected",
	}
	cols := map[string]string{"created_at": "u.created_at"}
	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			u := "/items?created_at_from=" + url.QueryEscape(payload) + "&created_at_to=" + url.QueryEscape(payload)
			req := httptest.NewRequest(http.MethodGet, u, nil)
			where, args := ParseDateRange(req, cols)
			assert.Contains(t, where, "u.created_at >= ?")
			assert.Contains(t, where, "u.created_at <= ?")
			for _, arg := range args {
				_, ok := arg.(string)
				assert.True(t, ok, "date args must be strings bound as params")
			}
		})
	}
}

// --- ParseFilters adversarial ---

func TestParseFilters_DuplicateKeys(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/items?role=admin&role=superadmin", nil)
	filters := ParseFilters(req, map[string]bool{"role": true})
	assert.NotEmpty(t, filters["role"])
}

func TestParseFilters_EmptyValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/items?role=&status=active", nil)
	filters := ParseFilters(req, map[string]bool{"role": true, "status": true})
	_, hasRole := filters["role"]
	assert.False(t, hasRole, "empty filter values should be excluded")
	assert.Equal(t, "active", filters["status"])
}

// --- Edge-case configs ---

func TestBuildListQuery_NilMaps(t *testing.T) {
	cfg := ListConfig{
		DefaultSort: "id",
	}
	params := ListParams{
		Sort:    "malicious",
		Filters: map[string]string{"anything": "value"},
	}
	result := BuildListQuery(params, cfg)
	assert.Contains(t, result.Order, "ORDER BY id ASC")
	assert.Equal(t, "", result.Where)
	assert.Empty(t, result.Args)
}

func TestBuildListQuery_ZeroMaxLimit(t *testing.T) {
	cfg := ListConfig{
		DefaultSort: "id",
		MaxLimit:    0,
	}
	params := ListParams{}
	result := BuildListQuery(params, cfg)
	assert.Contains(t, result.Order, "LIMIT 100")
}

func TestBuildListQuery_NegativeMaxLimit(t *testing.T) {
	cfg := ListConfig{
		DefaultSort: "id",
		MaxLimit:    -1,
	}
	params := ListParams{}
	result := BuildListQuery(params, cfg)
	assert.Contains(t, result.Order, "LIMIT 100")
}

func TestBuildListQuery_MaxLimitAboveAbsolute(t *testing.T) {
	cfg := ListConfig{
		DefaultSort: "id",
		MaxLimit:    5000,
	}
	params := ListParams{Limit: 5000}
	result := BuildListQuery(params, cfg)
	assert.Contains(t, result.Order, "LIMIT 1000")
}

func TestBuildListQuery_TableAliasUsedVerbatim(t *testing.T) {
	cfg := ListConfig{
		AllowedSort:   map[string]bool{"name": true},
		DefaultSort:   "name",
		SearchColumns: []string{"name"},
		MaxLimit:      50,
		TableAlias:    "tbl",
	}
	params := ListParams{Sort: "name", Search: "test"}
	result := BuildListQuery(params, cfg)
	assert.Contains(t, result.Order, "tbl.name")
	assert.Contains(t, result.Where, "tbl.name LIKE ?")
	assert.Contains(t, result.Where, "LIKE ?")
}

func TestBuildListQuery_EmptySearchColumns(t *testing.T) {
	cfg := ListConfig{
		DefaultSort:   "id",
		SearchColumns: []string{},
		MaxLimit:      50,
	}
	params := ListParams{Search: "anything"}
	result := BuildListQuery(params, cfg)
	assert.Equal(t, "", result.Where)
	assert.Empty(t, result.Args)
}

func TestBuildListQuery_WhitespaceSearch_StillSearches(t *testing.T) {
	params := ListParams{Search: "   "}
	result := BuildListQuery(params, adversarialConfig)
	assert.NotEqual(t, "", result.Where, "BuildListQuery treats non-empty search literally; trimming happens in ParseListParams")
}

func TestParseListParams_TrimsWhitespaceSearch(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/items?search=%20%20%20", nil)
	params := ParseListParams(req)
	assert.Equal(t, "", params.Search, "ParseListParams must trim whitespace-only search to empty")
	result := BuildListQuery(params, adversarialConfig)
	assert.Equal(t, "", result.Where)
}

func TestParseListParams_TruncatesLongSearch(t *testing.T) {
	longSearch := strings.Repeat("X", MaxSearchLength+500)
	req := httptest.NewRequest(http.MethodGet, "/items?search="+url.QueryEscape(longSearch), nil)
	params := ParseListParams(req)
	assert.Equal(t, MaxSearchLength, len(params.Search), "search must be truncated to MaxSearchLength")
}

// --- LIKE wildcard abuse ---

func TestBuildListQuery_LIKEWildcardAbuse(t *testing.T) {
	cases := []struct {
		name   string
		search string
	}{
		{"percent_only", "%"},
		{"underscore_only", "_"},
		{"double_percent", "%%"},
		{"wildcard_chain", "%a%b%c%d%e%f%g%h%"},
		{"underscore_chain", "________"},
		{"mixed_wildcards", "%__%_%__%"},
		{"percent_at_boundary", strings.Repeat("%", MaxSearchLength)},
		{"alternating", strings.Repeat("%_", MaxSearchLength/2)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params := ListParams{Search: tc.search}
			result := BuildListQuery(params, adversarialConfig)
			assert.Contains(t, result.Where, "LIKE ?")
			for _, arg := range result.Args {
				s, ok := arg.(string)
				if ok {
					assert.True(t, strings.HasPrefix(s, "%") && strings.HasSuffix(s, "%"),
						"search arg must be wrapped in %%, got len=%d", len(s))
				}
			}
		})
	}
}


// --- Date range semantic abuse ---

func TestParseDateRange_SemanticAbuse(t *testing.T) {
	cols := map[string]string{"created_at": "u.created_at"}

	cases := []struct {
		name  string
		query string
	}{
		{"inverted_range", "created_at_from=2099-12-31&created_at_to=2000-01-01"},
		{"non_date_string", "created_at_from=ZZZZZZZZZ&created_at_to=not-a-date"},
		{"epoch_zero", "created_at_from=0000-00-00&created_at_to=0000-00-00"},
		{"far_future", "created_at_from=9999-99-99&created_at_to=9999-99-99"},
		{"negative_date", "created_at_from=-1&created_at_to=-99999"},
		{"unix_timestamp", "created_at_from=1700000000&created_at_to=1800000000"},
		{"iso_with_timezone", "created_at_from=2024-01-01T00:00:00Z&created_at_to=2024-12-31T23:59:59%2B05:00"},
		{"only_from", "created_at_from=2024-01-01"},
		{"only_to", "created_at_to=2024-12-31"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/items?"+tc.query, nil)
			where, args := ParseDateRange(req, cols)
			assert.NotEqual(t, "", where, "should produce at least one condition")
			assert.Greater(t, len(args), 0, "should have at least one bound arg")
			assert.Contains(t, where, "u.created_at")
			assert.Contains(t, where, "?")
			assert.NotContains(t, where, "ZZZZZ")
		})
	}
}


func TestParseDateRange_UnknownColumns(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet,
		"/items?password_from=2024-01-01&secret_to=2024-12-31", nil)
	where, args := ParseDateRange(req, map[string]string{
		"created_at": "u.created_at",
	})
	assert.Equal(t, "", where)
	assert.Empty(t, args)
}

func TestParseDateRange_EmptyValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet,
		"/items?created_at_from=&created_at_to=", nil)
	where, args := ParseDateRange(req, map[string]string{
		"created_at": "u.created_at",
	})
	assert.Equal(t, "", where)
	assert.Empty(t, args)
}
