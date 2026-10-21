package token

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"time"

	authcode "github.com/eugenioenko/autentico/pkg/auth_code"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/devicecode"
	"github.com/eugenioenko/autentico/pkg/session"
	"github.com/eugenioenko/autentico/pkg/utils"
)

var (
	errGrantConsumed = errors.New("grant has already been consumed")
	errGrantExpired  = errors.New("grant has expired")
)

// storeGrantTokens makes credential consumption and token/session issuance atomic.
// No response or refresh cookie is sent until this transaction commits.
func storeGrantTokens(request TokenRequest, tokenRow Token, sessionRow session.Session) error {
	ctx := context.Background()
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
	if err := claimGrant(tx, request); err != nil {
		return err
	}
	if err := createToken(tx, tokenRow); err != nil {
		return err
	}
	if err := session.CreateSessionTx(tx, sessionRow); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		// database/sql marks the Tx done on a failed COMMIT even when SQLite
		// leaves its transaction open. Restore the writer before returning it.
		if _, rollbackErr := conn.ExecContext(ctx, "ROLLBACK"); rollbackErr != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			err = errors.Join(err, rollbackErr)
		}
		return err
	}
	return nil
}

func claimGrant(tx *sql.Tx, request TokenRequest) error {
	var expiryQuery string
	var credential string
	// RFC 6749 §4.1.2 / §6 and RFC 8628 §3.5: a conditional write decides
	// the winning redemption, including requests that passed validation together.
	switch request.GrantType {
	case "authorization_code":
		if err := authcode.MarkAuthCodeAsUsedTx(tx, request.Code); err != nil {
			if errors.Is(err, authcode.ErrCodeUsed) {
				return errGrantConsumed
			}
			return err
		}
		expiryQuery, credential = "SELECT expires_at FROM auth_codes WHERE code = ?", request.Code
	case "refresh_token":
		// RFC 6819 §5.2.2.3 / OAuth 2.1 §6.1: rotate refresh token — revoke old, issue new.
		credential = utils.HashToken(request.RefreshToken)
		result, err := tx.Exec(`UPDATE tokens SET revoked_at = ? WHERE refresh_token_hash = ? AND revoked_at IS NULL`, time.Now().UTC(), credential)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errGrantConsumed
		}
		expiryQuery = "SELECT refresh_token_expires_at FROM tokens WHERE refresh_token_hash = ?"
	case "urn:ietf:params:oauth:grant-type:device_code":
		if err := devicecode.ConsumeDeviceCodeTx(tx, request.DeviceCode); err != nil {
			if errors.Is(err, devicecode.ErrCodeConsumed) {
				return errGrantConsumed
			}
			return err
		}
		expiryQuery, credential = "SELECT expires_at FROM device_codes WHERE code = ?", request.DeviceCode
	}
	if expiryQuery != "" {
		var expiresAt time.Time
		if err := tx.QueryRow(expiryQuery, credential).Scan(&expiresAt); err != nil {
			return err
		}
		// RFC 6749 §4.1.2 / §6 and RFC 8628 §3.5: recheck expiry while holding
		// the write transaction; rollback also restores an expired credential's state.
		if !time.Now().Before(expiresAt) {
			return errGrantExpired
		}
	}
	return nil
}
