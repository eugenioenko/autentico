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

func parentIdentity(a *App, parentID string) (*user.User, error) {
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
	return usr, nil
}

func checkSession(a *App, credential string) (*user.User, string, error) {
	if len(credential) != 43 {
		return nil, "", errDenied
	}
	var id, parent string
	var created, expires time.Time
	err := db.GetDB().QueryRow(`SELECT id,idp_session_id,created_at,expires_at FROM forward_auth_sessions WHERE app_id=? AND token_hash=? AND revoked_at IS NULL`, a.ID, hash(credential)).Scan(&id, &parent, &created, &expires)
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
	now := time.Now()
	if now.Before(created) || !now.Before(expires) || !now.Before(created.Add(ttl)) {
		return nil, "", errDenied
	}
	usr, err := parentIdentity(a, parent)
	if err != nil {
		return nil, "", err
	}
	// Fail closed if activity persistence fails; successful proxy access counts
	// toward the existing central idle timeout without extending absolute age.
	if err = idpsession.UpdateLastActivity(parent); err != nil {
		return nil, "", err
	}
	if _, err = db.GetDB().Exec(`UPDATE forward_auth_sessions SET last_activity_at=? WHERE id=?`, now.UTC(), id); err != nil {
		return nil, "", err
	}
	return usr, id, nil
}
