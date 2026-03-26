package migrations

import (
	"database/sql"
	"fmt"
)

// SchemaVersion is the schema version this binary expects.
// Increment this and add a new Migration entry each time the schema changes.
var SchemaVersion = 1

// Migration represents a single schema change.
type Migration struct {
	Version int
	SQL     string
}

// migrations is the ordered list of schema changes.
// Version 1 is the baseline (the initial schema in db.go); no SQL needed here.
var migrations = []Migration{}

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
	if current < SchemaVersion {
		return fmt.Errorf(
			"database is at version %d, this binary requires version %d — run: autentico migrate",
			current, SchemaVersion,
		)
	}
	return nil
}

// Run applies any pending migrations. Prints "Already up to date." if none are needed.
func Run(db *sql.DB) error {
	current, err := getUserVersion(db)
	if err != nil {
		return err
	}
	if current >= SchemaVersion {
		fmt.Println("Already up to date.")
		return nil
	}
	for _, m := range migrations {
		if m.Version <= current {
			continue
		}
		fmt.Printf("Applying migration v%d...\n", m.Version)
		if _, err := db.Exec(m.SQL); err != nil {
			return fmt.Errorf("migrations: failed to apply v%d: %w", m.Version, err)
		}
		if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", m.Version)); err != nil {
			return fmt.Errorf("migrations: failed to set user_version to %d: %w", m.Version, err)
		}
		fmt.Printf("Migration v%d applied.\n", m.Version)
	}
	return nil
}
