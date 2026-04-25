package idpsession

import (
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

// DeactivateIdle finds all active IdP sessions whose last activity is older
// than the given timeout and cascade-deactivates each one (IdP session + child
// OAuth sessions + tokens). Returns the number of sessions deactivated.
func DeactivateIdle(timeout time.Duration) (int, error) {
	ids, err := getIdleSessionIDs(time.Now().Add(-timeout))
	if err != nil {
		return 0, fmt.Errorf("idpsession: %w", err)
	}

	for _, id := range ids {
		if err := DeactivateWithCascade(id); err != nil {
			return 0, fmt.Errorf("idpsession: cascade-deactivate %s: %w", id, err)
		}
	}
	return len(ids), nil
}

// DeactivateWithCascade deactivates an IdP (SSO) session and every OAuth
// session + token that was born from it, atomically.
//
// Revocation fan-out in order:
//  1. idp_sessions.deactivated_at is set (so /authorize stops accepting the cookie).
//  2. Every sessions row with idp_session_id = id is deactivated
//     (so /account and introspect treat them as dead).
//  3. Every tokens row whose access_token belongs to those sessions is revoked
//     (so ValidateBearer and /introspect fail them immediately).
//
// All three UPDATEs run inside a single transaction — a partial failure rolls
// back so the three tables can never disagree about whether a browser login
// is alive. Idempotent: calling on an already-deactivated id is a no-op for
// each table because of the "AND deactivated_at IS NULL" / "AND revoked_at IS
// NULL" guards.
func DeactivateWithCascade(idpSessionID string) error {
	if idpSessionID == "" {
		return fmt.Errorf("idpsession: empty idp_session_id")
	}

	tx, err := db.GetDB().Begin()
	if err != nil {
		return fmt.Errorf("idpsession: begin cascade tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()

	if _, err := tx.Exec(
		`UPDATE idp_sessions
		    SET deactivated_at = ?
		  WHERE id = ? AND deactivated_at IS NULL`,
		now, idpSessionID,
	); err != nil {
		return fmt.Errorf("idpsession: deactivate idp_session: %w", err)
	}

	if _, err := tx.Exec(
		`UPDATE sessions
		    SET deactivated_at = ?
		  WHERE idp_session_id = ? AND deactivated_at IS NULL`,
		now, idpSessionID,
	); err != nil {
		return fmt.Errorf("idpsession: deactivate child sessions: %w", err)
	}

	if _, err := tx.Exec(
		`UPDATE tokens
		    SET revoked_at = ?
		  WHERE access_token IN (
		          SELECT access_token FROM sessions WHERE idp_session_id = ?
		        )
		    AND revoked_at IS NULL`,
		now, idpSessionID,
	); err != nil {
		return fmt.Errorf("idpsession: revoke child tokens: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("idpsession: commit cascade tx: %w", err)
	}
	return nil
}
