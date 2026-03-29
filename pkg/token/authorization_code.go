package token

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/pkg/utils"
)

func UserByAuthorizationCode(w http.ResponseWriter, request TokenRequest) (*user.User, *authcode.AuthCode, error) {
	err := ValidateTokenRequestAuthorizationCode(request)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
		return nil, nil, err
	}

	code, err := authcode.AuthCodeByCode(request.Code)
	if err != nil {
		slog.Warn("token: authorization code not found", "error", err)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", fmt.Sprintf("%v", err))
		return nil, nil, err
	}

	// RFC 6749 §4.1.2: if the code has already been used, revoke all tokens
	// previously issued for this user+client before rejecting the request.
	if code.Used {
		slog.Warn("token: authorization code reuse detected — revoking issued tokens", "client_id", request.ClientID, "user_id", code.UserID)
		_ = RevokeTokensByUserAndClient(code.UserID, code.ClientID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Authorization code has already been used")
		return nil, nil, fmt.Errorf("authorization code has already been used")
	}

	if code.RedirectURI != request.RedirectURI || time.Now().After(code.ExpiresAt) {
		slog.Warn("token: authorization code invalid or expired", "client_id", request.ClientID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Authorization code is invalid or has expired")
		return nil, nil, fmt.Errorf("authorization code is invalid or has expired")
	}

	// Validate that client_id matches the one used when the code was issued
	if code.ClientID != "" && code.ClientID != request.ClientID {
		slog.Warn("token: client_id mismatch on code exchange", "expected_client", code.ClientID, "got_client", request.ClientID)
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Client ID mismatch")
		return nil, nil, fmt.Errorf("client ID mismatch")
	}

	// PKCE validation
	if code.CodeChallenge != "" {
		if request.CodeVerifier == "" {
			slog.Warn("token: PKCE code_verifier missing", "client_id", request.ClientID)
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "code_verifier is required")
			return nil, nil, fmt.Errorf("code_verifier is required")
		}
		// RFC 7636 §4.1: 43–128 chars, unreserved chars only
		if err := validateCodeVerifier(request.CodeVerifier); err != nil {
			slog.Warn("token: PKCE code_verifier invalid", "client_id", request.ClientID, "error", err)
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", fmt.Sprintf("code_verifier invalid: %v", err))
			return nil, nil, err
		}
		if !verifyCodeChallenge(code.CodeChallenge, code.CodeChallengeMethod, request.CodeVerifier) {
			slog.Warn("token: PKCE verification failed", "client_id", request.ClientID)
			utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return nil, nil, fmt.Errorf("PKCE verification failed")
		}
	}

	err = authcode.MarkAuthCodeAsUsed(request.Code)
	if err != nil {
		slog.Error("token: failed to mark authorization code as used", "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("Failed to mark authorization code as used: %v", err))
		return nil, nil, err
	}

	usr, err := user.UserByID(code.UserID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("%v", err))
		return nil, nil, err
	}
	return usr, code, nil
}

// codeVerifierRe matches the unreserved character set defined in RFC 3986 §2.3
// and required by RFC 7636 §4.1: ALPHA / DIGIT / "-" / "." / "_" / "~"
var codeVerifierRe = regexp.MustCompile(`^[A-Za-z0-9\-._~]+$`)

// validateCodeVerifier checks that the code_verifier satisfies RFC 7636 §4.1:
// length 43–128, unreserved characters only.
func validateCodeVerifier(v string) error {
	if len(v) < 43 || len(v) > 128 {
		return fmt.Errorf("code_verifier must be 43-128 characters, got %d", len(v))
	}
	if !codeVerifierRe.MatchString(v) {
		return fmt.Errorf("code_verifier contains invalid characters (unreserved chars only: A-Z a-z 0-9 - . _ ~)")
	}
	return nil
}

// verifyCodeChallenge validates the PKCE code_verifier against the stored code_challenge.
// For S256: BASE64URL(SHA256(code_verifier)) must equal code_challenge.
// For plain: code_verifier must equal code_challenge.
func verifyCodeChallenge(codeChallenge, method, codeVerifier string) bool {
	switch method {
	case "S256", "":
		// S256 is the default if no method specified but challenge exists
		hash := sha256.Sum256([]byte(codeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		return computed == codeChallenge
	case "plain":
		return codeVerifier == codeChallenge
	default:
		return false
	}
}
