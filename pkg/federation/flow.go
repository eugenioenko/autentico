package federation

import (
	"context"
	"crypto/rand"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
)

const federationFlowLifetime = 10 * time.Minute
const federationBrowserCookie = "autentico_federation"

var errInvalidLoginFlow = errors.New("invalid or expired federation login")

// browserCookieName uses a host-only, root-path cookie in secure deployments,
// preventing a sibling domain from planting the browser binding.
func browserCookieName() string {
	if config.GetBootstrap().AuthIdpSessionSecureCookie {
		return "__Host-" + federationBrowserCookie
	}
	return federationBrowserCookie
}

// randomFlowValue provides an independent 256-bit flow identifier or cookie.
func randomFlowValue() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

// validFlowValue limits cookies and identifiers to the server's canonical format.
func validFlowValue(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

// beginLoginFlow binds one signed authorization to a browser and a deadline.
// Reusing the browser cookie allows independent pending flows in different tabs.
func beginLoginFlow(r *http.Request, state *FederationState) (string, *http.Cookie, error) {
	binding := ""
	if cookie, err := r.Cookie(browserCookieName()); err == nil && validFlowValue(cookie.Value) {
		binding = cookie.Value
	}
	var err error
	if binding == "" {
		binding, err = randomFlowValue()
		if err != nil {
			return "", nil, err
		}
	}
	state.FlowID, err = randomFlowValue()
	if err != nil {
		return "", nil, err
	}
	now := time.Now().UTC()
	state.ExpiresAt = now.Add(federationFlowLifetime).Unix()
	signed, err := SignState(*state)
	if err != nil {
		return "", nil, err
	}
	// RFC 6749 §10.12 / RFC 9700 §4.7.1: the signed state is not itself a
	// browser credential; its one-use record requires the separate cookie.
	_, err = db.GetDB().ExecContext(r.Context(), `INSERT INTO federation_login_flows(flow_id,browser_hash,state_hash,expires_at) VALUES(?,?,?,?)`, state.FlowID, utils.HashSHA256(binding), utils.HashSHA256(signed), state.ExpiresAt)
	if err != nil {
		return "", nil, err
	}
	cookie := &http.Cookie{Name: browserCookieName(), Value: binding, Path: "/", HttpOnly: true,
		Secure: config.GetBootstrap().AuthIdpSessionSecureCookie, SameSite: http.SameSiteLaxMode,
		MaxAge: int(federationFlowLifetime / time.Second), Expires: now.Add(federationFlowLifetime)}
	return signed, cookie, nil
}

// consumeLoginFlow commits one browser-bound callback before any upstream
// request or local account/session mutation. Missing or wrong cookies never burn
// another browser's flow, and deletion prevents replay even with a retained cookie.
func consumeLoginFlow(r *http.Request, state *FederationState, signed string) error {
	cookie, err := r.Cookie(browserCookieName())
	if err != nil || !validFlowValue(cookie.Value) || !validFlowValue(state.FlowID) || time.Now().Unix() >= state.ExpiresAt {
		return errInvalidLoginFlow
	}
	ctx := r.Context()
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
	// RFC 9700 §4.7.1: acquire SQLite's writer before checking the deadline,
	// including when a different process holds the database write lock.
	if _, err := tx.ExecContext(ctx, `UPDATE federation_login_flows SET expires_at=expires_at WHERE flow_id=?`, state.FlowID); err != nil {
		return err
	}
	now := time.Now().Unix()
	if now >= state.ExpiresAt {
		return errInvalidLoginFlow
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM federation_login_flows WHERE flow_id=? AND browser_hash=? AND state_hash=? AND expires_at=? AND expires_at>?`, state.FlowID, utils.HashSHA256(cookie.Value), utils.HashSHA256(signed), state.ExpiresAt, now)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errInvalidLoginFlow
	}
	if err := tx.Commit(); err != nil {
		// SQLite can leave a failed COMMIT open after database/sql marks tx done.
		// Cleanup must not inherit a canceled request context or return a poisoned
		// connection to the pool; a failed rollback discards that connection.
		if _, rollbackErr := conn.ExecContext(context.Background(), "ROLLBACK"); rollbackErr != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			err = errors.Join(err, fmt.Errorf("rollback federation flow: %w", rollbackErr))
		}
		return err
	}
	return nil
}
