package account

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/bearer"
	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/passkey"
	"github.com/eugenioenko/autentico/pkg/reqid"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// HandleListPasskeys godoc
// @Summary List passkeys
// @Description Returns all registered passkeys for the authenticated user.
// @Tags account-security
// @Produce json
// @Security UserAuth
// @Success 200 {array} PasskeyResponse
// @Failure 401 {object} model.ApiError
// @Router /account/api/passkeys [get]
func HandleListPasskeys(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	creds, err := passkey.PasskeyCredentialsByUserID(usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	var response []PasskeyResponse
	for _, c := range creds {
		response = append(response, PasskeyResponse{
			ID:         c.ID,
			Name:       c.Name,
			CreatedAt:  c.CreatedAt,
			LastUsedAt: c.LastUsedAt,
		})
	}

	utils.SuccessResponse(w, response, http.StatusOK)
}

// HandleDeletePasskey godoc
// @Summary Delete a passkey
// @Description Deletes a registered passkey belonging to the authenticated user.
// @Tags account-security
// @Produce json
// @Param id path string true "Passkey ID"
// @Security UserAuth
// @Success 200 {object} map[string]string
// @Failure 400 {object} model.ApiError
// @Failure 401 {object} model.ApiError
// @Failure 403 {object} model.ApiError
// @Router /account/api/passkeys/{id} [delete]
func HandleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	passkeyID := r.PathValue("id")
	if passkeyID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing passkey ID")
		return
	}

	cred, err := passkey.PasskeyByID(passkeyID)
	if err != nil || cred.UserID != usr.ID {
		utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "Passkey not found or not owned by you")
		return
	}

	if err := passkey.DeletePasskeyCredential(passkeyID); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	audit.Log(audit.EventPasskeyRemoved, usr, audit.TargetUser, usr.ID, nil, utils.GetClientIP(r))
	utils.SuccessResponse(w, map[string]string{"message": "Passkey deleted"}, http.StatusOK)
}

// HandleRenamePasskey godoc
// @Summary Rename a passkey
// @Description Updates the display name of a registered passkey.
// @Tags account-security
// @Accept json
// @Produce json
// @Param id path string true "Passkey ID"
// @Param request body PasskeyRenameRequest true "Rename payload"
// @Security UserAuth
// @Success 200 {object} map[string]string
// @Failure 400 {object} model.ApiError
// @Failure 401 {object} model.ApiError
// @Failure 403 {object} model.ApiError
// @Router /account/api/passkeys/{id} [patch]
func HandleRenamePasskey(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	passkeyID := r.PathValue("id")
	if passkeyID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing passkey ID")
		return
	}

	var req PasskeyRenameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	cred, err := passkey.PasskeyByID(passkeyID)
	if err != nil || cred.UserID != usr.ID {
		utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "Passkey not found or not owned by you")
		return
	}

	if err := passkey.UpdatePasskeyName(passkeyID, req.Name); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "Passkey renamed"}, http.StatusOK)
}

// HandleAddPasskeyBegin godoc
// @Summary Begin passkey registration
// @Description Initiates a WebAuthn registration ceremony to add a new passkey to the authenticated user's account.
// @Tags account-security
// @Produce json
// @Security UserAuth
// @Success 200 {object} map[string]any "Challenge ID and WebAuthn creation options"
// @Failure 401 {object} model.ApiError
// @Failure 500 {object} model.ApiError
// @Router /account/api/passkeys/register/begin [post]
func HandleAddPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	existingCreds, _ := passkey.PasskeyCredentialsByUserID(usr.ID)
	wauthn, err := passkey.NewWebAuthn()
	if err != nil {
		slog.Error("account: passkey add: failed to initialize WebAuthn", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "WebAuthn initialization failed")
		return
	}

	challengeID, err := authcode.GenerateSecureCode()
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate challenge")
		return
	}

	wUser := passkey.WebAuthnUser{
		ID:          []byte(usr.ID),
		Name:        usr.Username,
		Credentials: passkey.CredentialsToWebAuthn(existingCreds),
	}
	creation, sessionData, err := wauthn.BeginRegistration(wUser,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		slog.Error("account: passkey add: failed to begin registration", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to begin registration")
		return
	}

	sessionJSON, _ := json.Marshal(sessionData)
	challenge := passkey.PasskeyChallenge{
		ID:            challengeID,
		UserID:        usr.ID,
		ChallengeData: string(sessionJSON),
		Type:          "account-registration",
		LoginState:    "",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	if err := passkey.CreatePasskeyChallenge(challenge); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to store challenge")
		return
	}

	utils.SuccessResponse(w, map[string]any{
		"challenge_id": challengeID,
		"options":      creation,
	}, http.StatusOK)
}

// HandleAddPasskeyFinish godoc
// @Summary Complete passkey registration
// @Description Completes the WebAuthn registration ceremony and stores the new passkey credential.
// @Tags account-security
// @Accept json
// @Produce json
// @Param challenge_id query string true "Challenge ID from begin registration"
// @Security UserAuth
// @Success 200 {object} map[string]string
// @Failure 400 {object} model.ApiError
// @Failure 401 {object} model.ApiError
// @Failure 403 {object} model.ApiError
// @Router /account/api/passkeys/register/finish [post]
func HandleAddPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	usr, err := bearer.UserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	challengeID := r.URL.Query().Get("challenge_id")
	if challengeID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing challenge_id")
		return
	}

	challenge, err := passkey.PasskeyChallengeByIDIncludingExpired(challengeID)
	if err != nil || challenge.Type != "account-registration" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid challenge")
		return
	}
	if challenge.Used || time.Now().After(challenge.ExpiresAt) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Challenge expired")
		return
	}
	if challenge.UserID != usr.ID {
		utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "Challenge does not belong to you")
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(challenge.ChallengeData), &sessionData); err != nil {
		slog.Error("account: passkey add: failed to parse session data", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to parse challenge")
		return
	}

	existingCreds, _ := passkey.PasskeyCredentialsByUserID(usr.ID)
	wUser := passkey.WebAuthnUser{
		ID:          []byte(usr.ID),
		Name:        usr.Username,
		Credentials: passkey.CredentialsToWebAuthn(existingCreds),
	}

	wauthn, err := passkey.NewWebAuthn()
	if err != nil {
		slog.Error("account: passkey add: failed to initialize WebAuthn", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "WebAuthn initialization failed")
		return
	}

	credential, err := wauthn.FinishRegistration(wUser, sessionData, r)
	if err != nil {
		slog.Warn("account: passkey add: registration failed", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "registration_failed", "Passkey registration failed")
		return
	}

	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
	credJSON, err := json.Marshal(credential)
	if err != nil {
		slog.Error("account: passkey add: failed to marshal credential", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to store credential")
		return
	}

	pCred := passkey.PasskeyCredential{
		ID:         credentialID,
		UserID:     usr.ID,
		Name:       passkey.GeneratePasskeyName(),
		Credential: string(credJSON),
	}
	if err := passkey.CreatePasskeyCredential(pCred); err != nil {
		slog.Error("account: passkey add: failed to store credential", "request_id", reqid.Get(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to store credential")
		return
	}

	_ = passkey.MarkPasskeyChallengeUsed(challenge.ID)
	audit.Log(audit.EventPasskeyAdded, usr, audit.TargetUser, usr.ID, nil, utils.GetClientIP(r))
	utils.SuccessResponse(w, map[string]string{"message": "Passkey added successfully"}, http.StatusOK)
}
