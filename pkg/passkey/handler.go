package passkey

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/middleware"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/go-webauthn/webauthn/webauthn"
)

// HandleLoginBegin starts a passkey authentication ceremony.
// @Summary Begin passkey login
// @Description Initiates a WebAuthn authentication ceremony. The user must already have a registered passkey. Returns the options for the navigator.credentials.get call.
// @Tags passkey
// @Accept json
// @Produce json
// @Param username query string true "User's username"
// @Param redirect_uri query string false "Redirect URI"
// @Param state query string false "OAuth2 state"
// @Param client_id query string false "OAuth2 client ID"
// @Success 200 {object} map[string]any "WebAuthn assertion options"
// @Router /oauth2/passkey/login/begin [get]
func HandleLoginBegin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	username := q.Get("username")
	if username == "" {
		writeJSONError(w, http.StatusBadRequest, "missing username")
		return
	}

	usr, err := user.UserByUsername(username)
	if err != nil {
		// Return generic error to avoid user enumeration
		writeJSONError(w, http.StatusBadRequest, "invalid username or passkey")
		return
	}

	creds, _ := PasskeyCredentialsByUserID(usr.ID)
	if len(creds) == 0 {
		writeJSONError(w, http.StatusBadRequest, "no passkeys registered for this user")
		return
	}

	loginState := LoginState{
		RedirectURI:            q.Get("redirect_uri"),
		State:               q.Get("state"),
		ClientID:            q.Get("client_id"),
		Scope:               q.Get("scope"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}
	stateJSON, err := json.Marshal(loginState)
	if err != nil {
		slog.Error("passkey: failed to serialize login state", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}

	wauthn, err := NewWebAuthn()
	if err != nil {
		slog.Error("passkey: failed to initialize WebAuthn", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}

	challengeID, err := authcode.GenerateSecureCode()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}

	// Has credentials: begin authentication
	webAuthnCreds := CredentialsToWebAuthn(creds)
	wUser := WebAuthnUser{
		ID:          []byte(usr.ID),
		Name:        usr.Username,
		Credentials: webAuthnCreds,
	}
	assertion, session, err := wauthn.BeginLogin(wUser)
	if err != nil {
		slog.Error("passkey: failed to begin login", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}
	sessionJSON, _ := json.Marshal(session)
	challenge := PasskeyChallenge{
		ID:            challengeID,
		UserID:        usr.ID,
		ChallengeData: string(sessionJSON),
		Type:          "authentication",
		LoginState:    string(stateJSON),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	if err := CreatePasskeyChallenge(challenge); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":         "authentication",
		"challenge_id": challengeID,
		"options":      assertion,
	})
}

// HandleLoginFinish completes a passkey authentication ceremony.
// @Summary Complete passkey login
// @Description Processes the WebAuthn assertion from the client and issues an authorization code.
// @Tags passkey
// @Accept json
// @Produce json
// @Param challenge_id query string true "Challenge ID from BeginLogin"
// @Param assertion body map[string]any true "WebAuthn assertion response"
// @Success 200 {object} map[string]string "Redirect URL"
// @Router /oauth2/passkey/login/finish [post]
func HandleLoginFinish(w http.ResponseWriter, r *http.Request) {
	challengeID := r.URL.Query().Get("challenge_id")
	if challengeID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing challenge_id")
		return
	}

	challenge, err := PasskeyChallengeByID(challengeID)
	if err != nil || challenge.Type != "authentication" {
		writeJSONError(w, http.StatusBadRequest, "invalid challenge")
		return
	}
	if challenge.Used || time.Now().After(challenge.ExpiresAt) {
		writeJSONError(w, http.StatusBadRequest, "challenge expired")
		return
	}

	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(challenge.ChallengeData), &session); err != nil {
		slog.Error("passkey: failed to parse session data", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}

	usr, err := user.UserByID(challenge.UserID)
	if err != nil {
		slog.Error("passkey: failed to get user", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}

	storedCreds, err := PasskeyCredentialsByUserID(usr.ID)
	if err != nil {
		slog.Error("passkey: failed to load credentials", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}

	wUser := WebAuthnUser{
		ID:          []byte(usr.ID),
		Name:        usr.Username,
		Credentials: CredentialsToWebAuthn(storedCreds),
	}

	wauthn, err := NewWebAuthn()
	if err != nil {
		slog.Error("passkey: failed to initialize WebAuthn", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}

	credential, err := wauthn.FinishLogin(wUser, session, r)
	if err != nil {
		slog.Warn("passkey: authentication failed", "request_id", middleware.GetRequestID(r.Context()), "error", err, "ip", utils.GetClientIP(r))
		writeJSONError(w, http.StatusUnauthorized, "authentication_failed")
		return
	}

	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
	_ = UpdatePasskeyCredential(credentialID, *credential)
	_ = MarkPasskeyChallengeUsed(challenge.ID)

	redirectURL, err := completeAuthFlow(w, r, usr, challenge.LoginState)
	if err != nil {
		slog.Error("passkey: failed to complete auth flow", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"redirect": redirectURL})
}

// HandleRegisterFinish completes a passkey registration ceremony.
// @Summary Complete passkey registration
// @Description Processes the WebAuthn attestation from the client and registers the passkey.
// @Tags passkey
// @Accept json
// @Produce json
// @Param challenge_id query string true "Challenge ID from BeginRegistration"
// @Param attestation body map[string]any true "WebAuthn attestation response"
// @Success 200 {object} map[string]string "Redirect URL"
// @Router /oauth2/passkey/register/finish [post]
func HandleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	challengeID := r.URL.Query().Get("challenge_id")
	if challengeID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing challenge_id")
		return
	}

	challenge, err := PasskeyChallengeByID(challengeID)
	if err != nil || challenge.Type != "registration" {
		writeJSONError(w, http.StatusBadRequest, "invalid challenge")
		return
	}
	if challenge.Used || time.Now().After(challenge.ExpiresAt) {
		writeJSONError(w, http.StatusBadRequest, "challenge expired")
		return
	}

	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(challenge.ChallengeData), &session); err != nil {
		slog.Error("passkey: failed to parse registration session data", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}

	usr, err := user.UserByID(challenge.UserID)
	if err != nil {
		slog.Error("passkey: failed to get user for registration", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}

	wUser := WebAuthnUser{
		ID:          []byte(usr.ID),
		Name:        usr.Username,
		Credentials: []webauthn.Credential{},
	}

	wauthn, err := NewWebAuthn()
	if err != nil {
		slog.Error("passkey: failed to initialize WebAuthn for registration", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}

	credential, err := wauthn.FinishRegistration(wUser, session, r)
	if err != nil {
		slog.Warn("passkey: registration failed", "request_id", middleware.GetRequestID(r.Context()), "error", err, "ip", utils.GetClientIP(r))
		writeJSONError(w, http.StatusBadRequest, "registration_failed")
		return
	}

	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
	credJSON, err := json.Marshal(credential)
	if err != nil {
		slog.Error("passkey: failed to marshal credential", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}

	pCred := PasskeyCredential{
		ID:         credentialID,
		UserID:     usr.ID,
		Name:       "",
		Credential: string(credJSON),
	}
	if err := CreatePasskeyCredential(pCred); err != nil {
		slog.Error("passkey: failed to store credential", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}

	_ = MarkPasskeyChallengeUsed(challenge.ID)

	redirectURL, err := completeAuthFlow(w, r, usr, challenge.LoginState)
	if err != nil {
		slog.Error("passkey: failed to complete auth flow after registration", "request_id", middleware.GetRequestID(r.Context()), "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"redirect": redirectURL})
}

// completeAuthFlow creates an IdP session and auth code, returning the redirect URL.
func completeAuthFlow(w http.ResponseWriter, r *http.Request, usr *user.User, loginStateJSON string) (string, error) {
	var loginState LoginState
	if err := json.Unmarshal([]byte(loginStateJSON), &loginState); err != nil {
		return "", fmt.Errorf("failed to restore login state")
	}

	cfg := config.Get()
	if cfg.AuthSsoSessionIdleTimeout > 0 {
		sessionID, err := authcode.GenerateSecureCode()
		if err == nil {
			session := idpsession.IdpSession{
				ID:        sessionID,
				UserID:    usr.ID,
				UserAgent: r.UserAgent(),
				IPAddress: utils.GetClientIP(r),
			}
			if idpsession.CreateIdpSession(session) == nil {
				idpsession.SetCookie(w, sessionID)
			}
		}
	}

	authorizationCode, err := authcode.GenerateSecureCode()
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization code")
	}

	ac := authcode.AuthCode{
		Code:                authorizationCode,
		UserID:              usr.ID,
		ClientID:            loginState.ClientID,
		RedirectURI:         loginState.RedirectURI,
		Scope:               loginState.Scope,
		Nonce:               loginState.Nonce,
		CodeChallenge:       loginState.CodeChallenge,
		CodeChallengeMethod: loginState.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(cfg.AuthAuthorizationCodeExpiration),
		Used:                false,
	}
	if err := authcode.CreateAuthCode(ac); err != nil {
		return "", fmt.Errorf("failed to create authorization code")
	}

	return fmt.Sprintf("%s?code=%s&state=%s", loginState.RedirectURI, ac.Code, loginState.State), nil
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
