package user

import (
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

// RevokeAllUserAccess revokes all tokens, OAuth sessions, and IdP sessions
// for a user. If excludeAccessToken is non-empty, the token and session
// matching that access token are kept alive (used after password change so
// the initiating session survives). Pass "" to revoke everything.
//
// All UPDATEs run inside a single transaction so the three tables never
// disagree about which sessions are alive.
func RevokeAllUserAccess(userID, excludeAccessToken string) error {
	tx, err := db.GetDB().Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()

	if _, err := tx.Exec(`UPDATE tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL AND access_token != ?`,
		now, userID, excludeAccessToken); err != nil {
		return fmt.Errorf("failed to revoke tokens: %v", err)
	}

	if _, err := tx.Exec(`UPDATE sessions SET deactivated_at = ? WHERE user_id = ? AND deactivated_at IS NULL AND access_token != ?`,
		now, userID, excludeAccessToken); err != nil {
		return fmt.Errorf("failed to deactivate sessions: %v", err)
	}

	if _, err := tx.Exec(`UPDATE idp_sessions SET deactivated_at = ?
		WHERE user_id = ? AND deactivated_at IS NULL
		AND id NOT IN (SELECT DISTINCT idp_session_id FROM sessions WHERE user_id = ? AND deactivated_at IS NULL AND idp_session_id IS NOT NULL)`,
		now, userID, userID); err != nil {
		return fmt.Errorf("failed to deactivate idp sessions: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}
	return nil
}

// HardDeleteUser permanently removes a user and all associated data.
// Tables with ON DELETE CASCADE (passkey_challenges, passkey_credentials, user_groups)
// are handled automatically. All others are deleted explicitly before removing the user row.
func HardDeleteUser(id string) error {
	d := db.GetDB()
	tables := []string{
		"deletion_requests",
		"tokens",
		"sessions",
		"auth_codes",
		"idp_sessions",
		"mfa_challenges",
		"trusted_devices",
		"federated_identities",
	}
	for _, table := range tables {
		if _, err := d.Exec(fmt.Sprintf(`DELETE FROM %s WHERE user_id = ?`, table), id); err != nil {
			return fmt.Errorf("failed to delete from %s: %w", table, err)
		}
	}
	if _, err := d.Exec(`DELETE FROM users WHERE id = ?`, id); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

// DeactivateUser sets deactivated_at and immediately revokes all tokens
// and deactivates all sessions/idp_sessions for the user.
func DeactivateUser(id string) error {
	// Set deactivated_at on the user
	result, err := db.GetDB().Exec(`UPDATE users SET deactivated_at = CURRENT_TIMESTAMP WHERE id = ? AND deactivated_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("failed to deactivate user: %v", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %v", err)
	}
	if rows == 0 {
		return fmt.Errorf("user not found or already deactivated")
	}

	return RevokeAllUserAccess(id, "")
}

// ReactivateUser clears deactivated_at, allowing the user to log in again.
func ReactivateUser(id string) error {
	result, err := db.GetDB().Exec(`UPDATE users SET deactivated_at = NULL WHERE id = ? AND deactivated_at IS NOT NULL`, id)
	if err != nil {
		return fmt.Errorf("failed to reactivate user: %v", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %v", err)
	}
	if rows == 0 {
		return fmt.Errorf("user not found or not deactivated")
	}
	return nil
}
