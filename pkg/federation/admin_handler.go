package federation

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleAdminFederationEndpoint routes admin CRUD requests for federation providers.
func HandleAdminFederationEndpoint(w http.ResponseWriter, r *http.Request) {
	providerID := extractProviderIDFromPath(r.URL.Path)

	if providerID == "" {
		switch r.Method {
		case http.MethodGet:
			handleListProviders(w, r)
		case http.MethodPost:
			handleCreateProvider(w, r)
		default:
			utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		}
	} else {
		switch r.Method {
		case http.MethodGet:
			handleGetProvider(w, r, providerID)
		case http.MethodPut:
			handleUpdateProvider(w, r, providerID)
		case http.MethodDelete:
			handleDeleteProvider(w, r, providerID)
		default:
			utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		}
	}
}

func handleListProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := ListFederationProviders()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	type ProviderResponse struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Issuer    string `json:"issuer"`
		ClientID  string `json:"client_id"`
		IconSVG   string `json:"icon_svg"`
		Enabled   bool   `json:"enabled"`
		SortOrder int    `json:"sort_order"`
	}

	var response []ProviderResponse
	for _, p := range providers {
		response = append(response, ProviderResponse{
			ID:        p.ID,
			Name:      p.Name,
			Issuer:    p.Issuer,
			ClientID:  p.ClientID,
			IconSVG:   p.IconSVG.String,
			Enabled:   p.Enabled,
			SortOrder: p.SortOrder,
		})
	}
	if response == nil {
		response = []ProviderResponse{}
	}

	utils.WriteApiResponse(w, response, http.StatusOK)
}

func handleGetProvider(w http.ResponseWriter, r *http.Request, id string) {
	p, err := FederationProviderByID(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Federation provider not found")
		return
	}

	type ProviderResponse struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Issuer    string `json:"issuer"`
		ClientID  string `json:"client_id"`
		IconSVG   string `json:"icon_svg"`
		Enabled   bool   `json:"enabled"`
		SortOrder int    `json:"sort_order"`
	}

	utils.WriteApiResponse(w, ProviderResponse{
		ID:        p.ID,
		Name:      p.Name,
		Issuer:    p.Issuer,
		ClientID:  p.ClientID,
		IconSVG:   p.IconSVG.String,
		Enabled:   p.Enabled,
		SortOrder: p.SortOrder,
	}, http.StatusOK)
}

func handleCreateProvider(w http.ResponseWriter, r *http.Request) {
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
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.WriteApiResponse(w, map[string]string{"status": "created"}, http.StatusCreated)
}

func handleUpdateProvider(w http.ResponseWriter, r *http.Request, id string) {
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

	utils.WriteApiResponse(w, map[string]string{"status": "updated"}, http.StatusOK)
}

func handleDeleteProvider(w http.ResponseWriter, r *http.Request, id string) {
	if _, err := FederationProviderByID(id); err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Federation provider not found")
		return
	}

	if err := DeleteFederationProvider(id); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// extractProviderIDFromPath extracts the provider ID from paths like /admin/api/federation/{id}
func extractProviderIDFromPath(path string) string {
	path = strings.TrimSuffix(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return ""
	}
	last := parts[len(parts)-1]
	if last == "federation" {
		return ""
	}
	return last
}
