package migrations

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
)

// SchemaVersion is the schema version this binary expects.
// Increment this and add a new Migration entry each time the schema changes.
var SchemaVersion = 22

// Migration represents a single schema change.
type Migration struct {
	Version int
	SQL     string
	// Major requires an offline backup when upgrading an existing database.
	Major bool
	// Func optionally transforms data after SQL, in the same transaction.
	// Use SQL for schema changes. Func must use tx and leave its lifecycle to Run.
	Func func(tx *sql.Tx) error
}

// migrations is the ordered list of schema changes.
var migrations = []Migration{
	{Version: 1, SQL: migration001},
	{Version: 2, SQL: migration002},
	{Version: 3, SQL: migration003},
	{Version: 4, SQL: migration004},
	{Version: 5, SQL: migration005},
	{Version: 6, SQL: migration006},
	{Version: 7, SQL: migration007},
	{Version: 8, SQL: migration008},
	{Version: 9, SQL: migration009},
	{Version: 10, SQL: migration010},
	{Version: 11, SQL: migration011},
	{Version: 12, SQL: migration012},
	{Version: 13, SQL: migration013},
	{Version: 14, SQL: migration014},
	{Version: 15, SQL: migration015, Major: true},
	{Version: 16, SQL: migration016},
	{Version: 17, SQL: migration017, Major: true, Func: encryptTotp},
	{Version: 18, SQL: migration018},
	{Version: 19, SQL: migration019},
	{Version: 20, SQL: migration020, Func: hashTrustedDevices},
	{Version: 21, SQL: migration021},
	{Version: 22, SQL: migration022},
}

func getUserVersion(db *sql.DB) (int, error) {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return 0, fmt.Errorf("migrations: failed to read user_version: %w", err)
	}
	return version, nil
}

// Check returns an error if the database schema is behind the expected version.
func Check(db *sql.DB) error {
	current, err := getUserVersion(db)
	if err != nil {
		return err
	}
	if current > SchemaVersion {
		return fmt.Errorf("database schema v%d is newer than this binary (v%d)", current, SchemaVersion)
	}
	if current < SchemaVersion {
		return fmt.Errorf(
			"database is at version %d, this binary requires version %d — run: autentico migrate",
			current, SchemaVersion,
		)
	}
	return nil
}

// Run applies any pending migrations. If verbose is true, prints progress and
// "Already up to date." when no migrations are needed.
func Run(db *sql.DB, verbose bool) error {
	return run(db, verbose, false)
}

func run(db *sql.DB, verbose, backedUp bool) error {
	current, err := getUserVersion(db)
	if err != nil {
		return err
	}
	if current > SchemaVersion {
		return fmt.Errorf("database schema v%d is newer than this binary (v%d)", current, SchemaVersion)
	}
	if current == SchemaVersion {
		if verbose {
			fmt.Println("Already up to date.")
		}
		return nil
	}
	// RFC 6238 §5.1: confirm the persistent key can recover existing seeds
	// before routine migrations advance an already encrypted database.
	if current >= 17 {
		if err := validateEncryptedTotp(db); err != nil {
			return fmt.Errorf("migrations: validate existing TOTP enrollments: %w", err)
		}
	}
	if current > 0 && !backedUp && pendingMajor(current) {
		var path string
		var seq int
		var name string
		if err := db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
			return err
		}
		if path != "" {
			return fmt.Errorf("major migration requires offline backup; use RunFile or autentico migrate")
		}
	}
	for _, m := range migrations {
		if m.Version <= current {
			continue
		}
		if verbose {
			fmt.Printf("Applying migration v%d...\n", m.Version)
		}
		if err := applyMigration(db, m); err != nil {
			return err
		}
		if verbose {
			fmt.Printf("Migration v%d applied.\n", m.Version)
		}
	}
	return nil
}

func pendingMajor(current int) bool {
	for _, m := range migrations {
		if m.Version > current && m.Major {
			return true
		}
	}
	return false
}

// applyMigration commits the schema, data transformation, and version together.
func applyMigration(db *sql.DB, m Migration) error {
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migrations: failed to acquire connection for v%d: %w", m.Version, err)
	}
	defer func() { _ = conn.Close() }()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrations: failed to begin v%d: %w", m.Version, err)
	}
	defer func() { _ = tx.Rollback() }()

	if m.SQL != "" {
		if _, err := tx.Exec(m.SQL); err != nil {
			return fmt.Errorf("migrations: failed to apply SQL for v%d: %w", m.Version, err)
		}
	}
	if m.Func != nil {
		if err := m.Func(tx); err != nil {
			return fmt.Errorf("migrations: failed to transform data for v%d: %w", m.Version, err)
		}
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", m.Version)); err != nil {
		return fmt.Errorf("migrations: failed to set user_version to %d: %w", m.Version, err)
	}
	if err := tx.Commit(); err != nil {
		// database/sql marks tx done even when COMMIT fails. SQLite can
		// leave it open (e.g. a deferred foreign-key violation), so roll
		// back on the same reserved connection before returning it.
		if _, rollbackErr := conn.ExecContext(ctx, "ROLLBACK"); rollbackErr != nil {
			// Never return a connection with unknown transaction state to the pool.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			err = errors.Join(err, fmt.Errorf("failed to roll back: %w", rollbackErr))
		}
		return fmt.Errorf("migrations: failed to commit v%d: %w", m.Version, err)
	}
	return nil
}
