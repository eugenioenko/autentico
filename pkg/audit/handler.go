package audit

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleListAuditLogs godoc
// @Summary List audit log events
// @Description Returns a paginated list of audit events with optional filters, search, sorting, and date range.
// @Tags admin-settings
// @Produce json
// @Security AdminAuth
// @Param event query string false "Filter by event type"
// @Param search query string false "Search actor_username, target_id, ip_address, detail"
// @Param sort query string false "Sort field (created_at, event)" default(created_at)
// @Param order query string false "Sort order (asc, desc)" default(desc)
// @Param created_at_from query string false "Date range start (ISO 8601)"
// @Param created_at_to query string false "Date range end (ISO 8601)"
// @Param limit query int false "Page size (default 100, max 200)"
// @Param offset query int false "Offset (default 0)"
// @Success 200 {object} model.ListResponse[AuditLogResponse]
// @Router /admin/api/audit-logs [get]
func HandleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	params := api.ParseListParams(r)
	params.Filters = api.ParseFilters(r, auditListConfig.AllowedFilters)

	if params.Order == "" {
		params.Order = "desc"
	}

	dateWhere, dateArgs := api.ParseDateRange(r, map[string]string{
		"created_at": "created_at",
	})

	logs, total, err := ListAuditLogsWithParams(params, dateWhere, dateArgs)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to read audit logs")
		return
	}

	items := make([]AuditLogResponse, len(logs))
	for i, l := range logs {
		items[i] = l.ToResponse()
	}

	utils.SuccessResponse(w, model.ListResponse[AuditLogResponse]{
		Items: items,
		Total: total,
	}, http.StatusOK)
}
