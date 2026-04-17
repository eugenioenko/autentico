package admin

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
)

type StatsResponse struct {
	TotalUsers              int `json:"total_users"`
	ActiveClients           int `json:"active_clients"`
	ActiveSessions          int `json:"active_sessions"`
	TotalSessions           int `json:"total_sessions"`
	RecentLogins            int `json:"recent_logins"`
	PendingDeletionRequests int `json:"pending_deletion_requests"`
}

// HandleStats returns system-wide statistics for the admin dashboard.
// @Summary System statistics
// @Description Returns a summary of users, clients, and active sessions.
// @Tags admin-settings
// @Produce json
// @Security AdminAuth
// @Success 200 {object} StatsResponse
// @Router /admin/api/stats [get]
func HandleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	var stats StatsResponse

	d := db.GetDB()

	_ = d.QueryRow(`SELECT COUNT(*) FROM users WHERE deactivated_at IS NULL`).Scan(&stats.TotalUsers)
	_ = d.QueryRow(`SELECT COUNT(*) FROM clients WHERE is_active = TRUE`).Scan(&stats.ActiveClients)
	_ = d.QueryRow(`SELECT COUNT(*) FROM sessions WHERE deactivated_at IS NULL AND expires_at > CURRENT_TIMESTAMP`).Scan(&stats.ActiveSessions)
	_ = d.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&stats.TotalSessions)
	_ = d.QueryRow(`SELECT COUNT(*) FROM sessions WHERE created_at > datetime('now', '-24 hours')`).Scan(&stats.RecentLogins)
	_ = d.QueryRow(`SELECT COUNT(*) FROM deletion_requests`).Scan(&stats.PendingDeletionRequests)

	utils.SuccessResponse(w, stats, http.StatusOK)
}
