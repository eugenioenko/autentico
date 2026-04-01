package audit

import (
	"net/http"
	"strconv"

	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleListAuditLogs godoc
// @Summary List audit log events
// @Description Returns a paginated list of audit events with optional filters.
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Param event query string false "Filter by event type"
// @Param actor_id query string false "Filter by actor user ID"
// @Param limit query int false "Page size (default 50)"
// @Param offset query int false "Offset (default 0)"
// @Success 200 {object} AuditLogListResponse
// @Router /admin/api/audit-logs [get]
func HandleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	event := r.URL.Query().Get("event")
	actorID := r.URL.Query().Get("actor_id")

	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	logs, total, err := ListAuditLogs(event, actorID, limit, offset)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to read audit logs")
		return
	}

	data := make([]AuditLogResponse, len(logs))
	for i, l := range logs {
		data[i] = l.ToResponse()
	}

	utils.SuccessResponse(w, AuditLogListResponse{Data: data, Total: total}, http.StatusOK)
}
