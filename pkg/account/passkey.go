package account

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/passkey"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func HandleListPasskeys(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
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

func HandleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
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

	utils.SuccessResponse(w, map[string]string{"message": "Passkey deleted"}, http.StatusOK)
}

func HandleRenamePasskey(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
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

func HandleAddPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	existingCreds, _ := passkey.PasskeyCredentialsByUserID(usr.ID)
	wauthn, err := passkey.NewWebAuthn()
	if err != nil {
		slog.Error("account: passkey add: failed to initialize WebAuthn", "request_id", middleware.GetRequestID(r.Context()), "error", err)
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
		slog.Error("account: passkey add: failed to begin registration", "request_id", middleware.GetRequestID(r.Context()), "error", err)
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

func HandleAddPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	challengeID := r.URL.Query().Get("challenge_id")
	if challengeID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing challenge_id")
		return
	}

	challenge, err := passkey.PasskeyChallengeByID(challengeID)
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
		slog.Error("account: passkey add: failed to parse session data", "request_id", middleware.GetRequestID(r.Context()), "error", err)
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
		slog.Error("account: passkey add: failed to initialize WebAuthn", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "WebAuthn initialization failed")
		return
	}

	credential, err := wauthn.FinishRegistration(wUser, sessionData, r)
	if err != nil {
		slog.Warn("account: passkey add: registration failed", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "registration_failed", "Passkey registration failed")
		return
	}

	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
	credJSON, err := json.Marshal(credential)
	if err != nil {
		slog.Error("account: passkey add: failed to marshal credential", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to store credential")
		return
	}

	pCred := passkey.PasskeyCredential{
		ID:         credentialID,
		UserID:     usr.ID,
		Name:       "",
		Credential: string(credJSON),
	}
	if err := passkey.CreatePasskeyCredential(pCred); err != nil {
		slog.Error("account: passkey add: failed to store credential", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to store credential")
		return
	}

	_ = passkey.MarkPasskeyChallengeUsed(challenge.ID)
	utils.SuccessResponse(w, map[string]string{"message": "Passkey added successfully"}, http.StatusOK)
}
