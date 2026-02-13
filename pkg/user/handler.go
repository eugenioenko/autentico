package user

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/jwtutil"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// getUserFromRequest extracts the user and role from the Authorization header
func getUserFromRequest(r *http.Request) (*User, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}
	tokenStr := utils.ExtractBearerToken(authHeader)
	if tokenStr == "" {
		return nil, fmt.Errorf("invalid Authorization header")
	}
	if _, err := jwtutil.ValidateAccessToken(tokenStr); err != nil {
		return nil, fmt.Errorf("invalid token: %v", err)
	}
	// Find session by access token
	session, err := session.SessionByAccessToken(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("invalid session: %v", err)
	}
	// Find user by session.UserID
	user, err := UserByID(session.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %v", err)
	}
	return user, nil
}

// HandleCreateUser godoc
// @Summary Create a new user
// @Description Registers a new user in the system
// @Tags users
// @Accept json
// @Produce json
// @Param user body UserCreateRequest true "User creation payload"
// @Success 201 {object} UserResponse
// @Failure 400 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /users/create [post]
func HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	_, err := getUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	var request UserCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request payload")
		return
	}
	err = ValidateUserCreateRequest(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("User validation error. %v", err))
		return
	}
	if config.Get().ValidationUsernameIsEmail && request.Email == "" {
		request.Email = request.Username
	}
	response, err := CreateUser(request.Username, request.Password, request.Email)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("User creation error. %v", err))
		return
	}
	utils.SuccessResponse(w, response, http.StatusCreated)
}

// HandleGetUser handles GET /user/{id} (read user by ID)
func HandleGetUser(w http.ResponseWriter, r *http.Request) {
	_, err := getUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id")
		return
	}
	result, err := UserByID(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	utils.SuccessResponse(w, result.ToResponse(), http.StatusOK)
}

// HandleUpdateUser handles PUT /user/{id} (update user)
func HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	_, err := getUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id")
		return
	}
	var req UserUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request payload")
		return
	}
	if err := ValidateUserUpdateRequest(req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	err = UpdateUser(id, req.Email, req.Role)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	result, err := UserByID(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, result.ToResponse(), http.StatusOK)
}

// HandleDeleteUser handles DELETE /user/{id}
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	_, err := getUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id")
		return
	}
	err = DeleteUser(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, map[string]string{"result": "deleted"}, http.StatusOK)
}

// HandleListUsers handles GET /admin/api/users - lists all active users
func HandleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := ListUsers()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	var response []UserResponse
	for _, u := range users {
		response = append(response, u.ToResponse())
	}

	if response == nil {
		response = []UserResponse{}
	}

	utils.SuccessResponse(w, response, http.StatusOK)
}

// HandleUnlockUser handles POST /admin/api/users/unlock?id=...
func HandleUnlockUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Only POST method is allowed")
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing user id")
		return
	}
	err := UnlockUser(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	result, err := UserByID(id)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	utils.SuccessResponse(w, result.ToResponse(), http.StatusOK)
}

// HandleUserAdminEndpoint is the combined handler for /admin/api/users
// Routes requests based on HTTP method
func HandleUserAdminEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		id := r.URL.Query().Get("id")
		if id != "" {
			HandleGetUser(w, r)
		} else {
			HandleListUsers(w, r)
		}
	case http.MethodPost:
		HandleCreateUser(w, r)
	case http.MethodPut:
		HandleUpdateUser(w, r)
	case http.MethodDelete:
		HandleDeleteUser(w, r)
	default:
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
	}
}
