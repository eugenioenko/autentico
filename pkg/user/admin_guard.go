package user

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"

	"github.com/eugenioenko/autentico/pkg/db"
)

// ErrLastActiveAdmin means a mutation would remove the final active admin.
var ErrLastActiveAdmin = errors.New("cannot remove the last active admin; create or promote another active admin first")

// mutateUser reserves SQLite's writer before checking the current account role.
// OWASP Authorization §Validate the Permissions on Every Request / §Exit Safely:
// enforce the last-admin policy (#481) before any destructive side effects, in
// the same transaction as the mutation, including across concurrent requests.
func mutateUser(id string, removesAdmin bool, change func(*sql.Tx) error) error {
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
	if removesAdmin {
		// A write before any read prevents deferred-transaction snapshot races.
		if _, err := tx.Exec(`UPDATE users SET id = id WHERE id = ?`, id); err != nil {
			return err
		}
		var last bool
		if err := tx.QueryRow(`SELECT EXISTS (
			SELECT 1 FROM users WHERE id = ? AND role = 'admin' AND deactivated_at IS NULL
			AND NOT EXISTS (SELECT 1 FROM users other WHERE other.id <> users.id
				AND other.role = 'admin' AND other.deactivated_at IS NULL))`, id).Scan(&last); err != nil {
			return err
		}
		if last {
			return ErrLastActiveAdmin
		}
	}
	if err := change(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		// SQLite may leave the transaction open after a failed deferred COMMIT.
		if _, rollbackErr := conn.ExecContext(ctx, "ROLLBACK"); rollbackErr != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			return errors.Join(err, rollbackErr)
		}
		return err
	}
	return nil
}
