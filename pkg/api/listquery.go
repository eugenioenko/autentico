package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const DefaultMaxLimit = 100
const AbsoluteMaxLimit = 1000
const MaxSearchLength = 200

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

	search := strings.TrimSpace(q.Get("search"))
	if len(search) > MaxSearchLength {
		search = search[:MaxSearchLength]
	}

	return ListParams{
		Sort:   q.Get("sort"),
		Order:  q.Get("order"),
		Search: search,
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

// dateFormats lists the accepted date/datetime formats in order of preference.
var dateFormats = []string{
	time.RFC3339,            // 2006-01-02T15:04:05Z07:00
	"2006-01-02T15:04:05",  // datetime without timezone
	"2006-01-02",           // date only
}

// parseDate attempts to parse a date string using the accepted formats.
// Returns the parsed time and nil error on success, or zero time and an error.
func parseDate(value string) (time.Time, error) {
	for _, layout := range dateFormats {
		if t, err := time.Parse(layout, value); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid date format %q: expected ISO 8601 (e.g. 2006-01-02 or 2006-01-02T15:04:05Z)", value)
}

// ParseDateRange reads "{param}_from" and "{param}_to" from the query string
// for each entry in columns (param prefix → qualified SQL column).
// Returns a WHERE fragment (with leading " AND ") and bound args.
// Returns an error if any date value is not a valid ISO 8601 date/datetime,
// or if _from is after _to for the same parameter.
func ParseDateRange(r *http.Request, columns map[string]string) (where string, args []any, err error) {
	var conditions []string
	for param, col := range columns {
		fromStr := r.URL.Query().Get(param + "_from")
		toStr := r.URL.Query().Get(param + "_to")

		var fromTime, toTime time.Time

		if fromStr != "" {
			fromTime, err = parseDate(fromStr)
			if err != nil {
				return "", nil, fmt.Errorf("invalid %s_from: %w", param, err)
			}
			conditions = append(conditions, col+" >= ?")
			args = append(args, fromStr)
		}
		if toStr != "" {
			toTime, err = parseDate(toStr)
			if err != nil {
				return "", nil, fmt.Errorf("invalid %s_to: %w", param, err)
			}
			conditions = append(conditions, col+" <= ?")
			args = append(args, toStr)
		}

		if fromStr != "" && toStr != "" && fromTime.After(toTime) {
			return "", nil, fmt.Errorf("invalid date range: %s_from (%s) is after %s_to (%s)", param, fromStr, param, toStr)
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
	if maxLimit > AbsoluteMaxLimit {
		maxLimit = AbsoluteMaxLimit
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
