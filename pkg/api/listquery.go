package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const DefaultMaxLimit = 100

type ListParams struct {
	Sort    string
	Order   string
	Search  string
	Filters map[string]string
	Limit   int
	Offset  int
}

type ListConfig struct {
	AllowedSort    map[string]bool
	SearchColumns  []string
	AllowedFilters map[string]bool
	DefaultSort    string
	MaxLimit       int
	TableAlias     string
}

func ParseListParams(r *http.Request) ListParams {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	return ListParams{
		Sort:   q.Get("sort"),
		Order:  q.Get("order"),
		Search: strings.TrimSpace(q.Get("search")),
		Limit:  limit,
		Offset: offset,
	}
}

func ParseFilters(r *http.Request, allowed map[string]bool) map[string]string {
	filters := make(map[string]string)
	for key := range allowed {
		if val := r.URL.Query().Get(key); val != "" {
			filters[key] = val
		}
	}
	return filters
}

// ParseDateRange reads "{param}_from" and "{param}_to" from the query string
// for each entry in columns (param prefix → qualified SQL column).
// Returns a WHERE fragment (with leading " AND ") and bound args.
func ParseDateRange(r *http.Request, columns map[string]string) (where string, args []any) {
	var conditions []string
	for param, col := range columns {
		if from := r.URL.Query().Get(param + "_from"); from != "" {
			conditions = append(conditions, col+" >= ?")
			args = append(args, from)
		}
		if to := r.URL.Query().Get(param + "_to"); to != "" {
			conditions = append(conditions, col+" <= ?")
			args = append(args, to)
		}
	}
	if len(conditions) > 0 {
		where = " AND " + strings.Join(conditions, " AND ")
	}
	return
}

type ListResult struct {
	Where string
	Order string
	Args  []any
}

func (cfg ListConfig) qualify(col string) string {
	if cfg.TableAlias != "" {
		return cfg.TableAlias + "." + col
	}
	return col
}

func BuildListQuery(params ListParams, cfg ListConfig) ListResult {
	var result ListResult
	var conditions []string

	if params.Search != "" && len(cfg.SearchColumns) > 0 {
		var searchParts []string
		pattern := "%" + params.Search + "%"
		for _, col := range cfg.SearchColumns {
			searchParts = append(searchParts, fmt.Sprintf("%s LIKE ?", cfg.qualify(col)))
			result.Args = append(result.Args, pattern)
		}
		conditions = append(conditions, "("+strings.Join(searchParts, " OR ")+")")
	}

	for col, val := range params.Filters {
		if cfg.AllowedFilters[col] {
			conditions = append(conditions, fmt.Sprintf("%s = ?", cfg.qualify(col)))
			result.Args = append(result.Args, val)
		}
	}

	if len(conditions) > 0 {
		result.Where = " AND " + strings.Join(conditions, " AND ")
	}

	sortCol := cfg.DefaultSort
	if params.Sort != "" && cfg.AllowedSort[params.Sort] {
		sortCol = params.Sort
	}
	sortCol = cfg.qualify(sortCol)
	order := "ASC"
	if strings.EqualFold(params.Order, "desc") {
		order = "DESC"
	}
	result.Order = fmt.Sprintf(" ORDER BY %s %s", sortCol, order)

	maxLimit := cfg.MaxLimit
	if maxLimit <= 0 {
		maxLimit = DefaultMaxLimit
	}
	limit := params.Limit
	if limit <= 0 || limit > maxLimit {
		limit = maxLimit
	}
	offset := params.Offset
	if offset < 0 {
		offset = 0
	}
	result.Order += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)

	return result
}
