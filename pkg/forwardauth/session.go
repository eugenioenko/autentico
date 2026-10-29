package forwardauth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	"github.com/eugenioenko/autentico/pkg/user"
)

func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type authenticatedParent struct {
	User        *user.User
	Session     *idpsession.IdpSession
	IdleTimeout time.Duration
}

func parentIdentity(a *App, parentID string) (*authenticatedParent, error) {
	parent, err := idpsession.IdpSessionByID(parentID)
	if err != nil {
		return nil, errDenied
	}
	c, err := client.ClientByClientID(a.ClientID)
	if err != nil {
		return nil, err
	}
	if !c.IsActive {
		return nil, errDenied
	}
	cfg := config.GetForClient(c.ToOverrides())
	usr, err := user.UserByID(parent.UserID)
	if err != nil {
		return nil, errDenied
	}
	// OIDC Core §3.1.2.3: enforce the same account, freshness and MFA policy
	// as /authorize; enrollment is not evidence of completed MFA.
	if !idpsession.IsFresh(parent, &cfg, time.Now()) || !idpsession.SatisfiesMfa(parent.MfaMethod, usr, &cfg) || cfg.RequireEmailVerification && !usr.IsEmailVerified && usr.Role != "admin" {
		return nil, errDenied
	}
	return &authenticatedParent{User: usr, Session: parent, IdleTimeout: cfg.AuthSsoSessionIdleTimeout}, nil
}

const activityWriteInterval = 30 * time.Second

func checkSession(a *App, credential string) (*user.User, string, error) {
	// Stored policy is enforced at authentication, never during admin recovery.
	if !a.IsActive || !a.validStored() || len(credential) != 43 {
		return nil, "", errDenied
	}
	var id, parent string
	var created, expires, last time.Time
	err := db.GetDB().QueryRow(`SELECT id,idp_session_id,created_at,expires_at,last_activity_at FROM forward_auth_sessions WHERE app_id=? AND token_hash=? AND revoked_at IS NULL`, a.ID, hash(credential)).Scan(&id, &parent, &created, &expires, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", errDenied
	}
	if err != nil {
		return nil, "", err
	}
	ttl, err := time.ParseDuration(a.SessionTTL)
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	if now.Before(created) || now.Before(last) || !now.Before(expires) || !now.Before(created.Add(ttl)) {
		return nil, "", errDenied
	}
	identity, err := parentIdentity(a, parent)
	if err != nil {
		return nil, "", err
	}
	// Avoid per-request writes even with short idle policies. Bound activity
	// granularity to a quarter of the effective idle limit, capped at 30s;
	// expiry is checked on every request and never extended by this batching.
	interval := activityWriteInterval
	if idle := identity.IdleTimeout; idle > 0 && idle/4 < interval {
		interval = idle / 4
	}
	if now.Sub(last) >= interval || now.Sub(identity.Session.LastActivityAt) >= interval {
		if err = touchActivity(id, parent, now, interval); err != nil {
			return nil, "", err
		}
	}
	return identity.User, id, nil
}

func touchActivity(id, parent string, now time.Time, interval time.Duration) error {
	tx, err := db.GetDB().Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	cutoff := now.Add(-interval)
	// Conditional updates coalesce concurrent checks that observed the same
	// old snapshot. Commit both activity timestamps together, failing closed
	// on any write error, without extending absolute session expiry.
	if _, err = tx.Exec(`UPDATE forward_auth_sessions SET last_activity_at=? WHERE id=? AND revoked_at IS NULL AND last_activity_at<?`, now, id, cutoff); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE idp_sessions SET last_activity_at=? WHERE id=? AND deactivated_at IS NULL AND last_activity_at<?`, now, parent, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}
