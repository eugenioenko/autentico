package admin

import (
	"net/http"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
)

type StatsResponse struct {
	TotalUsers              int `json:"total_users"`
	ActiveClients           int `json:"active_clients"`
	ActiveDevices           int `json:"active_devices"`
	ActiveTokens            int `json:"active_tokens"`
	RecentLogins            int `json:"recent_logins"`
	PendingDeletionRequests int `json:"pending_deletion_requests"`
	FailedLogins24h         int `json:"failed_logins_24h"`
	LockedAccounts          int `json:"locked_accounts"`
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

	d := db.GetReadDB()

	_ = d.QueryRow(`SELECT COUNT(*) FROM users WHERE deactivated_at IS NULL`).Scan(&stats.TotalUsers)
	_ = d.QueryRow(`SELECT COUNT(*) FROM clients WHERE is_active = TRUE`).Scan(&stats.ActiveClients)
	_ = d.QueryRow(`SELECT COUNT(*) FROM idp_sessions WHERE deactivated_at IS NULL`).Scan(&stats.ActiveDevices)
	_ = d.QueryRow(`SELECT COUNT(*) FROM tokens WHERE revoked_at IS NULL AND access_token_expires_at > CURRENT_TIMESTAMP`).Scan(&stats.ActiveTokens)
	_ = d.QueryRow(`SELECT COUNT(*) FROM sessions WHERE created_at > datetime('now', '-24 hours')`).Scan(&stats.RecentLogins)
	_ = d.QueryRow(`SELECT COUNT(*) FROM deletion_requests`).Scan(&stats.PendingDeletionRequests)
	_ = d.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE event = 'login_failed' AND created_at > datetime('now', '-24 hours')`).Scan(&stats.FailedLogins24h)
	_ = d.QueryRow(`SELECT COUNT(*) FROM users WHERE locked_until > CURRENT_TIMESTAMP AND deactivated_at IS NULL`).Scan(&stats.LockedAccounts)

	utils.SuccessResponse(w, stats, http.StatusOK)
}
