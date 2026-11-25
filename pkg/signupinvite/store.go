// Package signupinvite implements the local signup policy in rfc/signup-invites.md.
package signupinvite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
)

type Invite struct {
	ID       string     `json:"id"`
	Status   string     `json:"status"`
	Kind     string     `json:"kind"`
	Delivery string     `json:"delivery_method"`
	Email    string     `json:"email,omitempty"`
	MaxUses  *int       `json:"max_uses"`
	Uses     int        `json:"use_count"`
	Created  time.Time  `json:"created_at"`
	Expires  *time.Time `json:"expires_at"`
	Revoked  *time.Time `json:"revoked_at"`
	hash     string
}

const columns = "id, kind, delivery_method, COALESCE(email,''), max_uses, use_count, created_at, expires_at, revoked_at"
const available = "revoked_at IS NULL AND (expires_at IS NULL OR unixepoch(expires_at) > unixepoch()) AND (max_uses IS NULL OR use_count < max_uses)"

var ErrUnavailable = errors.New("invitation is unavailable")

func scan(row interface{ Scan(...any) error }) (*Invite, error) {
	var i Invite
	err := row.Scan(&i.ID, &i.Kind, &i.Delivery, &i.Email, &i.MaxUses, &i.Uses, &i.Created, &i.Expires, &i.Revoked, &i.Status)
	return &i, err
}

func cookie(raw string, age int) *http.Cookie {
	bs := config.GetBootstrap()
	return &http.Cookie{Name: config.HostCookieName(bs.AuthSignupInviteCookieName, bs.AuthCSRFSecureCookie), Value: raw, Path: "/", HttpOnly: true, Secure: bs.AuthCSRFSecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: age}
}

// Complete emits browser and audit effects only after the account transaction commits (§3).
func (i *Invite) Complete(w http.ResponseWriter, r *http.Request, userID string) {
	http.SetCookie(w, cookie("", -1))
	audit.Log("signup_invite_redeemed", audit.SimpleActor{ID: userID}, "signup_invite", i.ID, nil, utils.GetClientIP(r))
}

// Resolve requires both the public invitation ID and the secret held by this browser (§2).
func Resolve(r *http.Request, clientID, id string) (*Invite, error) {
	if id == "" {
		return nil, nil
	}
	c, err := r.Cookie(cookie("", 0).Name)
	if clientID != config.AccountClientID || err != nil {
		return nil, ErrUnavailable
	}
	hash := utils.HashToken(c.Value)
	i, err := scan(db.GetDB().QueryRow("SELECT "+columns+",'active' FROM signup_invites WHERE id=? AND token_hash=? AND "+available, id, hash))
	if err != nil {
		return nil, ErrUnavailable
	}
	i.hash = hash
	return i, nil
}

// Redeem runs the account and credential writes with the conditional use claim (§3).
func (i *Invite) Redeem(ctx context.Context, address string, create func(*sql.Tx, bool) error) error {
	conn, err := db.GetWriteDB().Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var verified bool
	err = tx.QueryRow("UPDATE signup_invites SET use_count=use_count+1 WHERE id=? AND token_hash=? AND (email IS NULL OR email=?) AND "+available+" RETURNING delivery_method='email'", i.ID, i.hash, address).Scan(&verified)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnavailable
	}
	if err != nil {
		return err
	}
	if err = create(tx, verified); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		if _, rb := conn.ExecContext(context.Background(), "ROLLBACK"); rb != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}
	return err
}
