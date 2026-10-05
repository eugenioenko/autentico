package account

import (
	"log/slog"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleListApps godoc
// @Summary List applications
// @Description Returns active clients an admin has marked show_in_account, for display on the account dashboard.
// @Tags account
// @Produce json
// @Security UserAuth
// @Success 200 {array} AppResponse
// @Failure 401 {object} model.ApiError
// @Router /account/api/apps [get]
func HandleListApps(w http.ResponseWriter, r *http.Request) {
	usr := middleware.UserFromContext(r.Context())
	if usr == nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	clients, err := client.ListAccountApps()
	if err != nil {
		slog.Error("account: failed to list apps", "error", err, "user_id", usr.ID)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to list applications")
		return
	}

	response := make([]AppResponse, 0, len(clients))
	for _, c := range clients {
		response = append(response, AppResponse{
			ClientID:    c.ClientID,
			Name:        c.ClientName,
			Description: c.Description,
			LogoURI:     c.LogoURI,
			ClientURI:   c.ClientURI,
		})
	}

	utils.SuccessResponse(w, response, http.StatusOK)
}
