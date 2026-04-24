package federation

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleListProviders godoc
// @Summary List federation providers
// @Description Lists federation providers with server-side sorting, filtering, search, and pagination.
// @Tags admin-federation
// @Produce json
// @Param sort query string false "Sort field (name, issuer, client_id, sort_order, enabled, created_at)"
// @Param order query string false "Sort order (asc, desc)" default(asc)
// @Param search query string false "Search by name, issuer, or client_id"
// @Param enabled query string false "Filter by enabled status (1, 0)"
// @Param limit query integer false "Max results per page (1–100)" default(100)
// @Param offset query integer false "Number of results to skip" default(0)
// @Security AdminAuth
// @Success 200 {object} model.ListResponse[ProviderResponse]
// @Router /admin/api/federation [get]
func HandleListProviders(w http.ResponseWriter, r *http.Request) {
	params := api.ParseListParams(r)
	params.Filters = api.ParseFilters(r, federationListConfig.AllowedFilters)
	if params.Order == "" {
		params.Order = "asc"
	}

	providers, total, err := ListFederationProvidersWithParams(params)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	items := make([]ProviderResponse, 0, len(providers))
	for _, p := range providers {
		items = append(items, toProviderResponse(*p))
	}

	utils.SuccessResponse(w, model.ListResponse[ProviderResponse]{Items: items, Total: total})
}

// HandleCreateProvider godoc
// @Summary Create a federation provider
// @Tags admin-federation
// @Accept json
// @Produce json
// @Param request body FederationProviderRequest true "Provider request"
// @Security AdminAuth
// @Success 201 {object} map[string]string
// @Router /admin/api/federation [post]
func HandleCreateProvider(w http.ResponseWriter, r *http.Request) {
	var req FederationProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid JSON payload")
		return
	}

	if req.ID == "" || req.Name == "" || req.Issuer == "" || req.ClientID == "" || req.ClientSecret == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "id, name, issuer, client_id, and client_secret are required")
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	p := FederationProvider{
		ID:           req.ID,
		Name:         req.Name,
		Issuer:       req.Issuer,
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		Enabled:      enabled,
		SortOrder:    req.SortOrder,
	}
	if req.IconSVG != "" {
		p.IconSVG.String = req.IconSVG
		p.IconSVG.Valid = true
	}

	if err := CreateFederationProvider(p); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "A federation provider with that ID already exists")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to create federation provider")
		return
	}

	audit.Log(audit.EventFederationCreated, audit.ActorFromRequest(r), audit.TargetFederation, req.ID, audit.Detail("name", req.Name), utils.GetClientIP(r))
	utils.WriteApiResponse(w, map[string]string{"status": "created"}, http.StatusCreated)
}

// HandleGetProvider godoc
// @Summary Get a federation provider
// @Tags admin-federation
// @Produce json
// @Param id path string true "Provider ID"
// @Security AdminAuth
// @Success 200 {object} ProviderResponse
// @Failure 404 {object} model.ApiError
// @Router /admin/api/federation/{id} [get]
func HandleGetProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := FederationProviderByID(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Federation provider not found")
		return
	}
	utils.WriteApiResponse(w, toProviderResponse(*p), http.StatusOK)
}

// HandleUpdateProvider godoc
// @Summary Update a federation provider
// @Tags admin-federation
// @Accept json
// @Produce json
// @Param id path string true "Provider ID"
// @Param request body FederationProviderRequest true "Provider request"
// @Security AdminAuth
// @Success 200 {object} map[string]string
// @Failure 404 {object} model.ApiError
// @Router /admin/api/federation/{id} [put]
func HandleUpdateProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := FederationProviderByID(id); err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Federation provider not found")
		return
	}

	var req FederationProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid JSON payload")
		return
	}

	if req.Name == "" || req.Issuer == "" || req.ClientID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "name, issuer, and client_id are required")
		return
	}

	if req.Enabled == nil {
		t := true
		req.Enabled = &t
	}

	if err := UpdateFederationProvider(id, req); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	audit.Log(audit.EventFederationUpdated, audit.ActorFromRequest(r), audit.TargetFederation, id, nil, utils.GetClientIP(r))
	utils.WriteApiResponse(w, map[string]string{"status": "updated"}, http.StatusOK)
}

// HandleDeleteProvider godoc
// @Summary Delete a federation provider
// @Tags admin-federation
// @Param id path string true "Provider ID"
// @Security AdminAuth
// @Success 204
// @Failure 404 {object} model.ApiError
// @Router /admin/api/federation/{id} [delete]
func HandleDeleteProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := FederationProviderByID(id); err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Federation provider not found")
		return
	}

	if err := DeleteFederationProvider(id); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	audit.Log(audit.EventFederationDeleted, audit.ActorFromRequest(r), audit.TargetFederation, id, nil, utils.GetClientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// ProviderResponse is the shared response shape for federation provider endpoints.
type ProviderResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Issuer    string `json:"issuer"`
	ClientID  string `json:"client_id"`
	IconSVG   string `json:"icon_svg"`
	Enabled   bool   `json:"enabled"`
	SortOrder int    `json:"sort_order"`
}

func toProviderResponse(p FederationProvider) ProviderResponse {
	return ProviderResponse{
		ID:        p.ID,
		Name:      p.Name,
		Issuer:    p.Issuer,
		ClientID:  p.ClientID,
		IconSVG:   p.IconSVG.String,
		Enabled:   p.Enabled,
		SortOrder: p.SortOrder,
	}
}
