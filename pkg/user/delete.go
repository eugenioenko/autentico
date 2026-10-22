package user

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
)

// RevokeAllUserAccess revokes all tokens, OAuth sessions, and IdP sessions
// for a user.
func RevokeAllUserAccess(userID string) error {
	return revokeUserAccess(userID, "")
}

// RevokeOtherUserAccess revokes all tokens, OAuth sessions, and IdP sessions
// for a user except the session identified by keepAccessToken.
func RevokeOtherUserAccess(userID, keepAccessToken string) error {
	return revokeUserAccess(userID, keepAccessToken)
}

// revokeUserAccess is the shared implementation. When excludeToken is empty,
// everything is revoked; otherwise the matching token/session is kept alive.
//
// All UPDATEs run inside a single transaction so the three tables never
// disagree about which sessions are alive.
func revokeUserAccess(userID, excludeToken string) error {
	return mutateUser(userID, false, func(tx *sql.Tx) error {
		return revokeUserAccessTx(tx, userID, excludeToken)
	})
}

// revokeUserAccessTx invalidates user credentials and linked sessions within the caller’s transaction.
func revokeUserAccessTx(tx *sql.Tx, userID, excludeToken string) error {
	now := time.Now()

	if excludeToken != "" {
		if _, err := tx.Exec(`UPDATE tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL AND access_token_hash != ?`,
			now, userID, utils.HashToken(excludeToken)); err != nil {
			return fmt.Errorf("failed to revoke tokens: %v", err)
		}
		if _, err := tx.Exec(`UPDATE sessions SET deactivated_at = ? WHERE user_id = ? AND deactivated_at IS NULL AND access_token_hash != ?`,
			now, userID, utils.HashToken(excludeToken)); err != nil {
			return fmt.Errorf("failed to deactivate sessions: %v", err)
		}
	} else {
		if _, err := tx.Exec(`UPDATE tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
			now, userID); err != nil {
			return fmt.Errorf("failed to revoke tokens: %v", err)
		}
		if _, err := tx.Exec(`UPDATE sessions SET deactivated_at = ? WHERE user_id = ? AND deactivated_at IS NULL`,
			now, userID); err != nil {
			return fmt.Errorf("failed to deactivate sessions: %v", err)
		}
	}

	if _, err := tx.Exec(`UPDATE idp_sessions SET deactivated_at = ?
		WHERE user_id = ? AND deactivated_at IS NULL
		AND id NOT IN (SELECT DISTINCT idp_session_id FROM sessions WHERE user_id = ? AND deactivated_at IS NULL AND idp_session_id IS NOT NULL)`,
		now, userID, userID); err != nil {
		return fmt.Errorf("failed to deactivate idp sessions: %v", err)
	}

	return nil
}

// HardDeleteUser permanently removes a user and all associated data.
// Tables with ON DELETE CASCADE (passkey_challenges, passkey_credentials, user_groups)
// are handled automatically. All others are deleted explicitly before removing the user row.
func HardDeleteUser(id string) error {
	return mutateUser(id, true, func(tx *sql.Tx) error {
		tables := []string{
			"deletion_requests",
			"tokens",
			"sessions",
			"auth_codes",
			"idp_sessions",
			"mfa_challenges",
			"trusted_devices",
			"federated_identities",
			"password_reset_tokens",
			"magic_link_tokens",
			"device_codes",
			"user_consents",
		}
		for _, table := range tables {
			if _, err := tx.Exec(fmt.Sprintf(`DELETE FROM %s WHERE user_id = ?`, table), id); err != nil {
				return fmt.Errorf("failed to delete from %s: %w", table, err)
			}
		}
		if _, err := tx.Exec(`DELETE FROM users WHERE id = ?`, id); err != nil {
			return fmt.Errorf("failed to delete user: %w", err)
		}
		return nil
	})
}

// DeactivateUser sets deactivated_at and immediately revokes all tokens
// and deactivates all sessions/idp_sessions for the user.
func DeactivateUser(id string) error {
	return mutateUser(id, true, func(tx *sql.Tx) error {
		// Set deactivated_at on the user
		result, err := tx.Exec(`UPDATE users SET deactivated_at = CURRENT_TIMESTAMP WHERE id = ? AND deactivated_at IS NULL`, id)
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

		return revokeUserAccessTx(tx, id, "")
	})
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
