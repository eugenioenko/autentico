package account

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/federation"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/passkey"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/trusteddevice"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/bcrypt"
)

func HandleGetProfile(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	utils.SuccessResponse(w, usr.ToResponse(), http.StatusOK)
}

func HandleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	var req user.UserUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	cfg := config.Get()

	if req.Username != "" && !cfg.AllowUsernameChange {
		utils.WriteErrorResponse(w, http.StatusForbidden, "not_allowed", "Username changes are not permitted")
		return
	}
	if req.Email != "" && !cfg.AllowEmailChange {
		utils.WriteErrorResponse(w, http.StatusForbidden, "not_allowed", "Email changes are not permitted")
		return
	}

	// Check email uniqueness if changing email
	if req.Email != "" && req.Email != usr.Email {
		if user.UserExistsByEmail(req.Email) {
			utils.WriteErrorResponse(w, http.StatusConflict, "email_taken", "Email address already in use")
			return
		}
	}

	// Allow updating profile fields only — exclude password, role, totp settings
	updateReq := user.UserUpdateRequest{
		Email:             req.Email,
		Username:          req.Username,
		GivenName:         req.GivenName,
		FamilyName:        req.FamilyName,
		PhoneNumber:       req.PhoneNumber,
		Picture:           req.Picture,
		Locale:            req.Locale,
		Zoneinfo:          req.Zoneinfo,
		AddressStreet:     req.AddressStreet,
		AddressLocality:   req.AddressLocality,
		AddressRegion:     req.AddressRegion,
		AddressPostalCode: req.AddressPostalCode,
		AddressCountry:    req.AddressCountry,
	}

	if err := user.ValidateUserUpdateRequest(updateReq); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	if err := user.UpdateUser(usr.ID, updateReq); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	updated, _ := user.UserByID(usr.ID)
	utils.SuccessResponse(w, updated.ToResponse(), http.StatusOK)
}

func HandleUpdatePassword(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	var req UpdatePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(usr.Password), []byte(req.CurrentPassword)); err != nil {
		utils.WriteErrorResponse(w, http.StatusForbidden, "invalid_password", "Current password does not match")
		return
	}

	// Validate new password
	if err := user.ValidateUserUpdateRequest(user.UserUpdateRequest{Password: req.NewPassword}); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	if err := user.UpdateUser(usr.ID, user.UserUpdateRequest{Password: req.NewPassword}); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "Password updated successfully"}, http.StatusOK)
}

func HandleListSessions(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	authHeader := r.Header.Get("Authorization")
	currentToken := utils.ExtractBearerToken(authHeader)

	sessions, err := session.ListSessionsByUser(usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	var response []SessionResponse
	for _, s := range sessions {
		if s.DeactivatedAt != nil {
			continue
		}
		response = append(response, SessionResponse{
			ID:             s.ID,
			UserAgent:      s.UserAgent,
			IPAddress:      s.IPAddress,
			LastActivityAt: s.LastActivityAt,
			CreatedAt:      s.CreatedAt,
			IsCurrent:      s.AccessToken == currentToken,
		})
	}

	utils.SuccessResponse(w, response, http.StatusOK)
}

func HandleRevokeSession(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	sessionID := r.PathValue("id")
	if sessionID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing session ID")
		return
	}

	// Fetch session to check ownership
	s, err := session.SessionByID(sessionID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusNotFound, "not_found", "Session not found")
		return
	}

	if s.UserID != usr.ID {
		utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "You cannot revoke someone else's session")
		return
	}

	// Check if it's the current session
	authHeader := r.Header.Get("Authorization")
	currentToken := utils.ExtractBearerToken(authHeader)
	if s.AccessToken == currentToken {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "You cannot revoke your current session from this endpoint. Use logout instead.")
		return
	}

	if err := session.DeactivateSessionByID(sessionID); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "Session revoked"}, http.StatusOK)
}

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

func HandleGetMfaStatus(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	utils.SuccessResponse(w, MfaStatusResponse{
		TotpEnabled: usr.TotpVerified,
	}, http.StatusOK)
}

func HandleSetupTotp(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	secret, url, err := mfa.GenerateTotpSecret(usr.Username, config.Get().PasskeyRPName)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	if err := user.StoreTotpSecretPending(usr.ID, secret); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, TotpSetupResponse{
		Secret:     secret,
		QrCodeData: url,
	}, http.StatusOK)
}

func HandleVerifyTotp(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	var req TotpVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	// Fetch user again to get the unverified secret
	currUser, _ := user.UserByID(usr.ID)
	if currUser.TotpSecret == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "TOTP not initiated")
		return
	}

	if !mfa.ValidateTotpCode(currUser.TotpSecret, req.Code) {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_code", "Invalid TOTP code")
		return
	}

	if err := user.SaveTotpSecret(usr.ID, currUser.TotpSecret); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "TOTP enabled successfully"}, http.StatusOK)
}

func HandleDeleteMfa(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	var req DisableMfaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	// Require password confirmation if the user has a password
	if usr.Password != "" {
		if err := bcrypt.CompareHashAndPassword([]byte(usr.Password), []byte(req.CurrentPassword)); err != nil {
			utils.WriteErrorResponse(w, http.StatusForbidden, "invalid_password", "Current password does not match")
			return
		}
	}

	if err := user.DisableMfa(usr.ID); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "MFA disabled"}, http.StatusOK)
}

func HandleListTrustedDevices(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	devices, err := trusteddevice.TrustedDevicesByUserID(usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	var response []TrustedDeviceResponse
	for _, d := range devices {
		response = append(response, TrustedDeviceResponse{
			ID:         d.ID,
			DeviceName: d.DeviceName,
			CreatedAt:  d.CreatedAt,
			LastUsedAt: d.LastUsedAt,
			ExpiresAt:  d.ExpiresAt,
		})
	}

	utils.SuccessResponse(w, response, http.StatusOK)
}

func HandleRevokeTrustedDevice(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	deviceID := r.PathValue("id")
	if deviceID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing device ID")
		return
	}

	device, err := trusteddevice.TrustedDeviceByID(deviceID)
	if err != nil || device.UserID != usr.ID {
		utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "Device not found or not owned by you")
		return
	}

	if err := trusteddevice.DeleteTrustedDevice(deviceID); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "Trusted device revoked"}, http.StatusOK)
}

func HandleListConnectedProviders(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	identities, err := federation.FederatedIdentitiesByUserID(usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	var response []ConnectedProviderResponse
	for _, fi := range identities {
		providerName := fi.ProviderID
		if provider, err := federation.FederationProviderByID(fi.ProviderID); err == nil {
			providerName = provider.Name
		}
		email := ""
		if fi.Email.Valid {
			email = fi.Email.String
		}
		response = append(response, ConnectedProviderResponse{
			ID:           fi.ID,
			ProviderID:   fi.ProviderID,
			ProviderName: providerName,
			Email:        email,
			CreatedAt:    fi.CreatedAt,
		})
	}

	utils.SuccessResponse(w, response, http.StatusOK)
}

func HandleDisconnectProvider(w http.ResponseWriter, r *http.Request) {
	usr, err := user.GetUserFromRequest(r)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	identityID := r.PathValue("id")
	if identityID == "" {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing identity ID")
		return
	}

	identities, err := federation.FederatedIdentitiesByUserID(usr.ID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	// Verify ownership
	var target *federation.FederatedIdentity
	for _, fi := range identities {
		if fi.ID == identityID {
			fi := fi
			target = fi
			break
		}
	}
	if target == nil {
		utils.WriteErrorResponse(w, http.StatusForbidden, "forbidden", "Identity not found or not owned by you")
		return
	}

	// Prevent lockout: user must have either a password or another federated identity
	if usr.Password == "" && len(identities) <= 1 {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "lockout_prevention", "Cannot disconnect your only login method")
		return
	}

	if err := federation.DeleteFederatedIdentity(identityID); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	utils.SuccessResponse(w, map[string]string{"message": "Provider disconnected"}, http.StatusOK)
}

func HandleGetSettings(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	utils.SuccessResponse(w, map[string]any{
		"auth_mode":                cfg.AuthMode,
		"mfa_enabled":              cfg.MfaEnabled,
		"mfa_method":               cfg.MfaMethod,
		"oauth_path":               config.GetBootstrap().AppOAuthPath,
		"allow_username_change":     cfg.AllowUsernameChange,
		"allow_email_change":        cfg.AllowEmailChange,
		"profile_field_given_name":  cfg.ProfileFieldGivenName,
		"profile_field_family_name": cfg.ProfileFieldFamilyName,
		"profile_field_phone":       cfg.ProfileFieldPhone,
		"profile_field_picture":     cfg.ProfileFieldPicture,
		"profile_field_locale":      cfg.ProfileFieldLocale,
		"profile_field_address":     cfg.ProfileFieldAddress,
	}, http.StatusOK)
}
