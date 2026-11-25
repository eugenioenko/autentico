package signupinvite

import (
	"net/http"
	"strings"
	"time"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	_ "github.com/eugenioenko/autentico/pkg/model" // Swagger envelope.
	"github.com/eugenioenko/autentico/pkg/utils"
)

type ListResponse struct {
	Items []Invite `json:"items"`
	Total int      `json:"total"`
	SMTP  bool     `json:"smtp_available"`
}

var listConfig = api.ListConfig{
	AllowedSort:    map[string]bool{"id": true, "kind": true, "delivery_method": true, "email": true, "use_count": true, "created_at": true, "expires_at": true, "status": true},
	SearchColumns:  []string{"id", "email"},
	AllowedFilters: map[string]bool{"kind": true, "delivery_method": true, "status": true},
	DefaultSort:    "created_at", TieBreaker: "id",
}

const inviteRows = ` FROM (SELECT signup_invites.*,
 CASE WHEN revoked_at IS NOT NULL THEN 'revoked'
      WHEN max_uses IS NOT NULL AND use_count>=max_uses THEN 'used'
      WHEN expires_at IS NOT NULL AND unixepoch(expires_at)<=? THEN 'expired'
      ELSE 'active' END AS status
 FROM signup_invites) WHERE 1=1`

// HandleList godoc
// @Summary List signup invitations
// @Tags signup invites
// @Security AdminAuth
// @Produce json
// @Param search query string false "Search recipient email or public invitation ID"
// @Param kind query string false "Invitation type" Enums(personal,shared)
// @Param delivery_method query string false "Delivery method" Enums(link,email)
// @Param status query string false "Invitation status" Enums(active,used,expired,revoked)
// @Param created_at_from query string false "First creation date (ISO 8601)"
// @Param created_at_to query string false "Last creation date (ISO 8601)"
// @Param sort query string false "Sort field" Enums(id,kind,delivery_method,email,use_count,created_at,expires_at,status)
// @Param order query string false "Sort direction" Enums(asc,desc) default(desc)
// @Param limit query integer false "Maximum rows (1–100)" default(100)
// @Param offset query integer false "Rows to skip" default(0)
// @Success 200 {object} model.ApiResponse[signupinvite.ListResponse]
// @Failure 400 {object} model.ApiError
// @Router /admin/api/signup-invites [get]
func HandleList(w http.ResponseWriter, r *http.Request) {
	params := api.ParseListParams(r)
	if params.Order == "" {
		params.Order = "desc"
	}
	params.Filters = api.ParseFilters(r, listConfig.AllowedFilters)
	dates, dateArgs, err := api.ParseDateRange(r, map[string]string{"created_at": "julianday(created_at)"})
	if err != nil {
		utils.ErrorResponse(w, err.Error(), 400)
		return
	}
	// Compare instants even when clients send offsets or date-only bounds.
	dates = strings.ReplaceAll(dates, " ?", " julianday(?)")
	query := api.BuildListQuery(params, listConfig)
	from := inviteRows + query.Where + dates
	args := append([]any{time.Now().Unix()}, query.Args...)
	args = append(args, dateArgs...)
	result := ListResponse{Items: []Invite{}, SMTP: config.Get().SmtpHost != ""}
	// Use one read snapshot so counts and page contents agree during redemption.
	tx, err := db.GetReadDB().BeginTx(r.Context(), nil)
	if err != nil {
		utils.ErrorResponse(w, "Could not list invites", 500)
		return
	}
	defer func() { _ = tx.Rollback() }()
	if err = tx.QueryRowContext(r.Context(), "SELECT COUNT(*)"+from, args...).Scan(&result.Total); err != nil {
		utils.ErrorResponse(w, "Could not count invites", 500)
		return
	}
	rows, err := tx.QueryContext(r.Context(), "SELECT "+columns+",status"+from+query.Order, args...)
	if err != nil {
		utils.ErrorResponse(w, "Could not list invites", 500)
		return
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		i, err := scan(rows)
		if err != nil {
			utils.ErrorResponse(w, "Could not read invite", 500)
			return
		}
		result.Items = append(result.Items, *i)
	}
	if rows.Err() != nil {
		utils.ErrorResponse(w, "Could not list invites", 500)
		return
	}
	utils.SuccessResponse(w, result)
}
