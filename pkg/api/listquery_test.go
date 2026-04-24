package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testConfig = ListConfig{
	AllowedSort:    map[string]bool{"name": true, "created_at": true, "email": true},
	SearchColumns:  []string{"name", "email"},
	AllowedFilters: map[string]bool{"role": true, "active": true},
	DefaultSort:    "created_at",
	MaxLimit:       50,
}

func TestParseListParams_Defaults(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/items", nil)
	params := ParseListParams(req)

	assert.Equal(t, "", params.Sort)
	assert.Equal(t, "", params.Order)
	assert.Equal(t, "", params.Search)
	assert.Equal(t, 0, params.Limit)
	assert.Equal(t, 0, params.Offset)
}

func TestParseListParams_AllFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/items?sort=name&order=desc&search=john&limit=20&offset=5", nil)
	params := ParseListParams(req)

	assert.Equal(t, "name", params.Sort)
	assert.Equal(t, "desc", params.Order)
	assert.Equal(t, "john", params.Search)
	assert.Equal(t, 20, params.Limit)
	assert.Equal(t, 5, params.Offset)
}

func TestParseFilters(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/items?role=admin&active=true&evil=drop", nil)
	filters := ParseFilters(req, testConfig.AllowedFilters)

	assert.Equal(t, "admin", filters["role"])
	assert.Equal(t, "true", filters["active"])
	_, exists := filters["evil"]
	assert.False(t, exists)
}

func TestBuildListQuery_DefaultSort(t *testing.T) {
	params := ListParams{}
	result := BuildListQuery(params, testConfig)

	assert.Equal(t, "", result.Where)
	assert.Contains(t, result.Order, "ORDER BY created_at ASC")
	assert.Contains(t, result.Order, "LIMIT 50 OFFSET 0")
	assert.Empty(t, result.Args)
}

func TestBuildListQuery_CustomSort(t *testing.T) {
	params := ListParams{Sort: "name", Order: "desc"}
	result := BuildListQuery(params, testConfig)

	assert.Contains(t, result.Order, "ORDER BY name DESC")
}

func TestBuildListQuery_InvalidSort_FallsBackToDefault(t *testing.T) {
	params := ListParams{Sort: "DROP TABLE users;--"}
	result := BuildListQuery(params, testConfig)

	assert.Contains(t, result.Order, "ORDER BY created_at ASC")
}

func TestBuildListQuery_Search(t *testing.T) {
	params := ListParams{Search: "john"}
	result := BuildListQuery(params, testConfig)

	assert.Contains(t, result.Where, "name LIKE ?")
	assert.Contains(t, result.Where, "email LIKE ?")
	assert.Contains(t, result.Where, " OR ")
	assert.Len(t, result.Args, 2)
	assert.Equal(t, "%john%", result.Args[0])
	assert.Equal(t, "%john%", result.Args[1])
}

func TestBuildListQuery_Filters(t *testing.T) {
	params := ListParams{
		Filters: map[string]string{"role": "admin"},
	}
	result := BuildListQuery(params, testConfig)

	assert.Contains(t, result.Where, "role = ?")
	assert.Contains(t, result.Args, "admin")
}

func TestBuildListQuery_LimitCapped(t *testing.T) {
	params := ListParams{Limit: 999}
	result := BuildListQuery(params, testConfig)

	assert.Contains(t, result.Order, "LIMIT 50")
}

func TestBuildListQuery_SearchAndFilter(t *testing.T) {
	params := ListParams{
		Search:  "test",
		Filters: map[string]string{"role": "user"},
	}
	result := BuildListQuery(params, testConfig)

	assert.Contains(t, result.Where, "name LIKE ?")
	assert.Contains(t, result.Where, "role = ?")
	assert.Contains(t, result.Where, " AND ")
	assert.Len(t, result.Args, 3)
}
