package token

import (
	"net/http"
	"strings"
	"time"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/utils"
)

type AdminTokenResponse struct {
	ID                   string  `json:"id"`
	UserID               *string `json:"user_id"`
	Username             string  `json:"username"`
	Email                string  `json:"email"`
	Scope                string  `json:"scope"`
	GrantType            string  `json:"grant_type"`
	AccessTokenExpiresAt string  `json:"access_token_expires_at"`
	IssuedAt             string  `json:"issued_at"`
	RevokedAt            *string `json:"revoked_at"`
	Status               string  `json:"status"`
}

func tokenRowToResponse(r TokenRow) AdminTokenResponse {
	resp := AdminTokenResponse{
		ID:                   r.ID,
		UserID:               r.UserID,
		Username:             r.Username,
		Email:                r.Email,
		Scope:                r.Scope,
		GrantType:            r.GrantType,
		AccessTokenExpiresAt: r.AccessTokenExpiresAt.Format(time.RFC3339),
		IssuedAt:             r.IssuedAt.Format(time.RFC3339),
		Status:               "active",
	}
	if r.RevokedAt != nil {
		t := r.RevokedAt.Format(time.RFC3339)
		resp.RevokedAt = &t
		resp.Status = "revoked"
	} else if r.AccessTokenExpiresAt.Before(time.Now()) {
		resp.Status = "expired"
	}
	return resp
}

// HandleListTokens godoc
// @Summary List tokens
// @Description Returns paginated tokens with user info, sorting, search, and date filtering.
// @Tags admin-tokens
// @Produce json
// @Param sort query string false "Sort field (issued_at, access_token_expires_at)"
// @Param order query string false "Sort order (asc, desc)" default(desc)
// @Param search query string false "Search across username and email"
// @Param limit query integer false "Max results per page (1–100)" default(100)
// @Param offset query integer false "Number of results to skip" default(0)
// @Param issued_at_from query string false "Filter tokens issued after (ISO 8601)"
// @Param issued_at_to query string false "Filter tokens issued before (ISO 8601)"
// @Security AdminAuth
// @Success 200 {object} model.ListResponse[AdminTokenResponse]
// @Router /admin/api/tokens [get]
func HandleListTokens(w http.ResponseWriter, r *http.Request) {
	params := api.ParseListParams(r)
	dateWhere, dateArgs := api.ParseDateRange(r, map[string]string{
		"issued_at": "t.issued_at",
	})

	tokens, total, err := ListTokensWithParams(params, dateWhere, dateArgs)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	items := make([]AdminTokenResponse, 0, len(tokens))
	for _, t := range tokens {
		items = append(items, tokenRowToResponse(t))
	}

	utils.SuccessResponse(w, model.ListResponse[AdminTokenResponse]{
		Items: items,
		Total: total,
	}, http.StatusOK)
}

// HandleRevokeToken godoc
// @Summary Revoke a token
// @Description Revokes a token by its ID.
// @Tags admin-tokens
// @Produce json
// @Param id path string true "Token ID"
// @Security AdminAuth
// @Success 200 {object} map[string]string
// @Router /admin/api/tokens/{id} [delete]
func HandleRevokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing token id")
		return
	}

	if err := RevokeByID(id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Token not found or already revoked")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	audit.Log(audit.EventTokenRevoked, audit.ActorFromRequest(r), audit.TargetToken, id, nil, utils.GetClientIP(r))
	utils.SuccessResponse(w, map[string]string{"result": "revoked"}, http.StatusOK)
}
