package client

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/eugenioenko/autentico/pkg/utils"
)

// HandleRegister handles POST /oauth2/register - creates a new client
// @Summary Register a new OAuth2 client
// @Description Registers a new OAuth2/OIDC client (admin only)
// @Tags client
// @Accept json
// @Produce json
// @Param request body ClientCreateRequest true "Client registration request"
// @Success 201 {object} ClientResponse
// @Failure 400 {object} model.AuthErrorResponse
// @Failure 401 {object} model.AuthErrorResponse
// @Failure 500 {object} model.AuthErrorResponse
// @Router /oauth2/register [post]
func HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Only POST method is allowed")
		return
	}

	var request ClientCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid JSON payload")
		return
	}

	if err := ValidateClientCreateRequest(request); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if err := ValidateRedirectURIs(request.RedirectURIs); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid redirect URI: "+err.Error())
		return
	}

	response, err := CreateClient(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.WriteApiResponse(w, response, http.StatusCreated)
}

// HandleGetClient handles GET /oauth2/register/{client_id} - gets client info
// @Summary Get client information
// @Description Retrieves information about a registered client (admin only)
// @Tags client
// @Accept json
// @Produce json
// @Param client_id path string true "Client ID"
// @Success 200 {object} ClientInfoResponse
// @Failure 404 {object} model.AuthErrorResponse
// @Router /oauth2/register/{client_id} [get]
func HandleGetClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Only GET method is allowed")
		return
	}

	clientID := extractClientIDFromPath(r.URL.Path)
	if clientID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Client ID is required")
		return
	}

	client, err := ClientByClientID(clientID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "invalid_client", "Client not found")
		return
	}

	utils.WriteApiResponse(w, client.ToInfoResponse(), http.StatusOK)
}

// HandleUpdateClient handles PUT /oauth2/register/{client_id} - updates a client
// @Summary Update client information
// @Description Updates a registered client (admin only)
// @Tags client
// @Accept json
// @Produce json
// @Param client_id path string true "Client ID"
// @Param request body ClientUpdateRequest true "Client update request"
// @Success 200 {object} ClientInfoResponse
// @Failure 400 {object} model.AuthErrorResponse
// @Failure 404 {object} model.AuthErrorResponse
// @Router /oauth2/register/{client_id} [put]
func HandleUpdateClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Only PUT method is allowed")
		return
	}

	clientID := extractClientIDFromPath(r.URL.Path)
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
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if len(request.RedirectURIs) > 0 {
		if err := ValidateRedirectURIs(request.RedirectURIs); err != nil {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid redirect URI: "+err.Error())
			return
		}
	}

	response, err := UpdateClient(clientID, request)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			utils.WriteErrorResponse(w, http.StatusNotFound, "invalid_client", "Client not found")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.WriteApiResponse(w, response, http.StatusOK)
}

// HandleDeleteClient handles DELETE /oauth2/register/{client_id} - deactivates a client
// @Summary Deactivate a client
// @Description Deactivates (soft deletes) a registered client (admin only)
// @Tags client
// @Accept json
// @Produce json
// @Param client_id path string true "Client ID"
// @Success 204 "No Content"
// @Failure 404 {object} model.AuthErrorResponse
// @Router /oauth2/register/{client_id} [delete]
func HandleDeleteClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Only DELETE method is allowed")
		return
	}

	clientID := extractClientIDFromPath(r.URL.Path)
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

	w.WriteHeader(http.StatusNoContent)
}

// HandleListClients handles GET /oauth2/register - lists all clients
// @Summary List all clients
// @Description Lists all registered clients (admin only)
// @Tags client
// @Accept json
// @Produce json
// @Success 200 {array} ClientInfoResponse
// @Failure 500 {object} model.AuthErrorResponse
// @Router /oauth2/register [get]
func HandleListClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Only GET method is allowed")
		return
	}

	clients, err := ListClients()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	var response []*ClientInfoResponse
	for _, c := range clients {
		response = append(response, c.ToInfoResponse())
	}

	// Return empty array instead of null if no clients
	if response == nil {
		response = []*ClientInfoResponse{}
	}

	utils.WriteApiResponse(w, response, http.StatusOK)
}

// HandleClientEndpoint is a combined handler for /oauth2/register endpoints
// Routes requests based on method and path
func HandleClientEndpoint(w http.ResponseWriter, r *http.Request) {
	// Extract client_id from path if present
	clientID := extractClientIDFromPath(r.URL.Path)

	if clientID == "" {
		// /oauth2/register - collection operations
		switch r.Method {
		case http.MethodPost:
			HandleRegister(w, r)
		case http.MethodGet:
			HandleListClients(w, r)
		default:
			utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		}
	} else {
		// /oauth2/register/{client_id} - individual client operations
		switch r.Method {
		case http.MethodGet:
			HandleGetClient(w, r)
		case http.MethodPut:
			HandleUpdateClient(w, r)
		case http.MethodDelete:
			HandleDeleteClient(w, r)
		default:
			utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		}
	}
}

// extractClientIDFromPath extracts the client_id from a path like /oauth2/register/{client_id}
func extractClientIDFromPath(path string) string {
	// Remove trailing slash if present
	path = strings.TrimSuffix(path, "/")

	// Split path and get the last segment
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return ""
	}

	lastPart := parts[len(parts)-1]

	// If the last part is "register", there's no client_id
	if lastPart == "register" {
		return ""
	}

	return lastPart
}
