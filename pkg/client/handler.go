package client

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/model"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleRegister handles POST /oauth2/register (RFC 7591) and POST /admin/api/clients - creates a new client
// @Summary Register a new OAuth2 client
// @Description Registers a new OAuth2/OIDC client. Also available at /oauth2/register (RFC 7591 Dynamic Client Registration).
// @Tags admin-client
// @Accept json
// @Produce json
// @Param request body ClientCreateRequest true "Client registration request"
// @Security AdminAuth
// @Success 201 {object} ClientResponse
// @Failure 400 {object} model.AuthErrorResponse
// @Failure 500 {object} model.AuthErrorResponse
// @Router /oauth2/register [post]
// @Router /admin/api/clients [post]
func HandleRegister(w http.ResponseWriter, r *http.Request) {
	// RFC 7591 §3: The client registration endpoint MUST accept HTTP POST messages
	// with request parameters encoded in the entity body using the 'application/json' format.
	// RFC 7591 §2: The server MUST ignore any client metadata it does not understand.
	// (Go's json.Decoder silently ignores unknown fields by default.)
	var request ClientCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid JSON payload")
		return
	}

	if err := ValidateClientCreateRequest(request); err != nil {
		// RFC 7591 §3.2.2: invalid_client_metadata when a metadata field value is invalid.
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}

	if err := ValidateRedirectURIs(request.RedirectURIs); err != nil {
		// RFC 7591 §3.2.2: invalid_redirect_uri when redirect URI values are invalid.
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_redirect_uri", "Invalid redirect URI: "+err.Error())
		return
	}

	var response *ClientResponse
	var err error
	if request.ClientID != "" {
		response, err = CreateClientWithID(request.ClientID, request)
	} else {
		response, err = CreateClient(request)
	}
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	// RFC 7591 §3.2.1: The server MUST return all registered metadata about this client.
	audit.Log(audit.EventClientCreated, audit.ActorFromRequest(r), audit.TargetClient, response.ClientID, nil, utils.GetClientIP(r))
	utils.WriteApiResponse(w, response, http.StatusCreated)
}

// HandleGetClient handles GET /oauth2/register/{client_id} (RFC 7591) and GET /admin/api/clients/{client_id}
// @Summary Get client information
// @Description Retrieves information about a registered client. Also available at /oauth2/register/{client_id}.
// @Tags admin-client
// @Produce json
// @Param client_id path string true "Client ID"
// @Security AdminAuth
// @Success 200 {object} ClientInfoResponse
// @Failure 404 {object} model.AuthErrorResponse
// @Router /oauth2/register/{client_id} [get]
// @Router /admin/api/clients/{client_id} [get]
func HandleGetClient(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("client_id")
	if clientID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Client ID is required")
		return
	}

	c, err := ClientByClientIDIncludingDisabled(clientID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "invalid_client", "Client not found")
		return
	}

	utils.WriteApiResponse(w, c.ToInfoResponse(), http.StatusOK)
}

// HandleUpdateClient handles PUT /oauth2/register/{client_id} (RFC 7591) and PUT /admin/api/clients/{client_id}
// @Summary Update client information
// @Description Updates a registered client. Also available at /oauth2/register/{client_id}.
// @Tags admin-client
// @Accept json
// @Produce json
// @Param client_id path string true "Client ID"
// @Param request body ClientUpdateRequest true "Client update request"
// @Security AdminAuth
// @Success 200 {object} ClientInfoResponse
// @Failure 400 {object} model.AuthErrorResponse
// @Failure 404 {object} model.AuthErrorResponse
// @Router /oauth2/register/{client_id} [put]
// @Router /admin/api/clients/{client_id} [put]
func HandleUpdateClient(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("client_id")
	if clientID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Client ID is required")
		return
	}

	var request ClientUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid JSON payload")
		return
	}

	if err := ValidateClientUpdateRequest(request); err != nil {
		// RFC 7591 §3.2.2: invalid_client_metadata when a metadata field value is invalid.
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}

	if len(request.RedirectURIs) > 0 {
		if err := ValidateRedirectURIs(request.RedirectURIs); err != nil {
			// RFC 7591 §3.2.2: invalid_redirect_uri when redirect URI values are invalid.
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_redirect_uri", "Invalid redirect URI: "+err.Error())
			return
		}
	}

	err := UpdateClient(clientID, request)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "invalid_client", "Client not found")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	audit.Log(audit.EventClientUpdated, audit.ActorFromRequest(r), audit.TargetClient, clientID, nil, utils.GetClientIP(r))
	updated, _ := ClientByClientIDIncludingDisabled(clientID)
	utils.WriteApiResponse(w, updated.ToInfoResponse(), http.StatusOK)
}

// HandleDeleteClient handles DELETE /oauth2/register/{client_id} (RFC 7591) and DELETE /admin/api/clients/{client_id}
// @Summary Deactivate a client
// @Description Deactivates (soft deletes) a registered client. Also available at /oauth2/register/{client_id}.
// @Tags admin-client
// @Param client_id path string true "Client ID"
// @Security AdminAuth
// @Success 204 "No Content"
// @Failure 404 {object} model.AuthErrorResponse
// @Router /oauth2/register/{client_id} [delete]
// @Router /admin/api/clients/{client_id} [delete]
func HandleDeleteClient(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("client_id")
	if clientID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Client ID is required")
		return
	}

	err := DeleteClient(clientID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "invalid_client", "Client not found")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	audit.Log(audit.EventClientDeleted, audit.ActorFromRequest(r), audit.TargetClient, clientID, nil, utils.GetClientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// HandleAdminListClients handles GET /admin/api/clients and GET /oauth2/register with search, sort, filter, pagination
// @Summary List clients with pagination
// @Description Lists clients with server-side sorting, filtering, search, and pagination.
// @Tags admin-client
// @Produce json
// @Security AdminAuth
// @Param sort query string false "Sort field (created_at, client_name, client_id, client_type)"
// @Param order query string false "Sort order (asc, desc)"
// @Param search query string false "Search by client_name or client_id"
// @Param client_type query string false "Filter by client type (confidential, public)"
// @Param is_active query string false "Filter by active status (1, 0)"
// @Param limit query int false "Page size (max 200)"
// @Param offset query int false "Offset"
// @Success 200 {object} model.ListResponse[ClientInfoResponse]
// @Failure 500 {object} model.AuthErrorResponse
// @Router /admin/api/clients [get]
func HandleAdminListClients(w http.ResponseWriter, r *http.Request) {
	params := api.ParseListParams(r)
	params.Filters = api.ParseFilters(r, clientListConfig.AllowedFilters)
	if params.Order == "" {
		params.Order = "desc"
	}

	clients, total, err := ListClientsWithParams(params)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	var items []*ClientInfoResponse
	for _, c := range clients {
		items = append(items, c.ToInfoResponse())
	}
	if items == nil {
		items = []*ClientInfoResponse{}
	}

	utils.SuccessResponse(w, model.ListResponse[*ClientInfoResponse]{Items: items, Total: total})
}
