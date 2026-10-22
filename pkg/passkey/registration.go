package passkey

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
)

const registrationLifetime = 5 * time.Minute

func registrationPolicy(clientID, email string) (int, error) {
	c, err := client.ClientByClientID(clientID)
	if err != nil {
		return http.StatusBadRequest, err
	}
	cfg := config.GetForClient(c.ToOverrides())
	// WebAuthn §7.1: the RP's account registration policy also applies to ceremonies.
	if !cfg.AuthAllowSelfSignup || (cfg.AuthMode != "password_and_passkey" && cfg.AuthMode != "passkey_only") {
		return http.StatusForbidden, errors.New("passkey signup is disabled")
	}
	if cfg.RequireEmailVerification {
		if email == "" {
			return http.StatusBadRequest, errors.New("email is required for verification")
		}
		if cfg.SmtpHost == "" {
			return http.StatusServiceUnavailable, errors.New("email verification is unavailable")
		}
	}
	return 0, nil
}

func registrationCookieName() string {
	if config.GetBootstrap().AuthCSRFSecureCookie {
		return "__Host-autentico_passkey_registration"
	}
	return "autentico_passkey_registration"
}

func registrationOwner(r *http.Request) string {
	cookie, err := r.Cookie(registrationCookieName())
	if err != nil {
		return ""
	}
	return cookie.Value
}

func setRegistrationCookie(w http.ResponseWriter, challengeID string) {
	// RFC 6265 §4.1.2.5–6: keep the ceremony binding host-only and inaccessible to JS.
	cookie := &http.Cookie{
		Name: registrationCookieName(), Value: challengeID, Path: "/",
		Secure: config.GetBootstrap().AuthCSRFSecureCookie, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		MaxAge: int(registrationLifetime.Seconds()), Expires: time.Now().Add(registrationLifetime),
	}
	if challengeID == "" {
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(1, 0)
	}
	http.SetCookie(w, cookie)
}

// deletePendingRegistration checks eligibility and deletes in one transaction. A live
// ceremony belongs to its browser; abandoned accounts become available on expiry.
// Credentials or a completed registration always prevent deletion, including when
// a parallel finish request has just saved them.
func deletePendingRegistration(userID, owner string) (bool, error) {
	tx, err := db.GetDB().Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	deleted, err := deletePendingRegistrationTx(tx, userID, owner)
	if err != nil || !deleted {
		return false, err
	}
	return true, tx.Commit()
}

// deletePendingRegistrationTx removes only abandoned, unregistered non-admin accounts.
func deletePendingRegistrationTx(tx *sql.Tx, userID, owner string) (bool, error) {
	var createdAt time.Time
	// OWASP Authorization §Validate the Permissions on Every Request: an
	// account promoted to admin is never abandoned registration cleanup.
	err := tx.QueryRow(`SELECT created_at FROM users WHERE id = ?
		AND role <> 'admin' AND registered_at IS NULL AND (password IS NULL OR password = '') AND deactivated_at IS NULL
		AND NOT EXISTS (SELECT 1 FROM passkey_credentials WHERE user_id = users.id)`, userID).Scan(&createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	now := time.Now()
	rows, err := tx.Query(`SELECT id, expires_at FROM passkey_challenges
		WHERE user_id = ? AND type = 'registration' AND used = FALSE`, userID)
	if err != nil {
		return false, err
	}
	owned, active := false, false
	for rows.Next() {
		var id string
		var expires time.Time
		if err := rows.Scan(&id, &expires); err != nil {
			_ = rows.Close()
			return false, err
		}
		if now.Before(expires) {
			active = true
			owned = owned || (owner != "" && id == owner)
		}
	}
	rowErr := rows.Err()
	_ = rows.Close()
	if rowErr != nil {
		return false, rowErr
	}
	if !owned && (active || now.Before(createdAt.Add(registrationLifetime))) {
		return false, nil
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE id = ?`, userID); err != nil {
		return false, err
	}
	return true, nil
}
