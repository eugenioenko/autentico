package migrations

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/dbguard"
	"github.com/eugenioenko/autentico/pkg/sqliteutil"
	"github.com/eugenioenko/autentico/pkg/totpsecret"
	_ "modernc.org/sqlite"
)

// recoveryState is persisted before any upgrade writes. An interrupted major
// upgrade is restored before retry, even if some earlier migrations committed.
type recoveryState struct {
	Backup  string      `json:"backup"`
	SHA256  string      `json:"sha256"`
	Version int         `json:"version"`
	Mode    os.FileMode `json:"mode"`
	Owner   *fileOwner  `json:"owner,omitempty"`
}

type fileOwner struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
}

func openFile(path string, readOnly bool) (*sql.DB, error) {
	u := sqliteutil.FileURL(path)
	q := u.Query()
	q.Add("_pragma", "busy_timeout(1000)")
	q.Add("_pragma", "foreign_keys(1)")
	if readOnly {
		q.Set("mode", "ro")
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err == nil {
		db.SetMaxOpenConns(1)
	}
	return db, err
}

// InspectFile reads the schema version and pending major upgrades without
// creating or migrating a database. Empty databases require no major approval.
func InspectFile(path string) (int, []int, error) {
	path, err := dbguard.Path(path)
	if err != nil {
		return 0, nil, err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return 0, nil, nil
	} else if err != nil {
		return 0, nil, err
	}
	db, err := openFile(path, true)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = db.Close() }()
	version, err := getUserVersion(db)
	if err != nil {
		return 0, nil, err
	}
	populated, err := hasSchema(db)
	if err != nil {
		return 0, nil, err
	}
	if !populated {
		return version, nil, nil
	}
	return version, MajorVersions(version), nil
}

// ValidateCurrentFile checks an up-to-date database under a shared lock, so an
// idempotent deployment check can run alongside the service without upgrading it.
func ValidateCurrentFile(path string) error {
	if err := totpsecret.ValidateKey(config.GetBootstrap().TotpEncryptionKey); err != nil {
		return err
	}
	path, err := dbguard.Path(path)
	if err != nil {
		return err
	}
	lock, err := dbguard.Acquire(path, false)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := RecoveryPending(path); err != nil {
		return err
	}
	db, err := openFile(path, true)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if err := Check(db); err != nil {
		return err
	}
	return validateEncryptedTotp(db)
}

// MajorVersions returns the major schema versions pending after current.
func MajorVersions(current int) []int {
	var versions []int
	for _, m := range migrations {
		if m.Major && m.Version > current {
			versions = append(versions, m.Version)
		}
	}
	return versions
}

// ValidateApprovals rejects unknown versions, so an automation typo cannot
// accidentally approve an unrelated or future destructive upgrade.
func ValidateApprovals(approved []int) error {
	for _, version := range approved {
		known := false
		for _, m := range migrations {
			known = known || (m.Major && m.Version == version)
		}
		if !known {
			return fmt.Errorf("schema %d is not a known major migration", version)
		}
	}
	return nil
}

// MissingMajorApprovals is shared by the interactive CLI and migration runner.
func MissingMajorApprovals(required, approved []int) []int {
	var missing []int
	for _, version := range required {
		found := false
		for _, value := range approved {
			found = found || version == value
		}
		if !found {
			missing = append(missing, version)
		}
	}
	return missing
}

func hasSchema(db *sql.DB) (bool, error) {
	var tables int
	err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables)
	return tables > 0, err
}

func requireApprovals(required, approved []int) error {
	if err := ValidateApprovals(approved); err != nil {
		return err
	}
	if missing := MissingMajorApprovals(required, approved); len(missing) > 0 {
		version := missing[0]
		return fmt.Errorf("major schema migration %d requires explicit approval; run autentico migrate interactively or with --approve-major=%d", version, version)
	}
	return nil
}

// CheckAuto rejects major upgrades before startup runs any migrations. Fresh
// databases have no data to protect and may initialize automatically.
func CheckAuto(db *sql.DB) error {
	version, err := getUserVersion(db)
	if err != nil {
		return err
	}
	if version > SchemaVersion {
		return fmt.Errorf("database schema v%d is newer than this binary (v%d)", version, SchemaVersion)
	}
	populated, err := hasSchema(db)
	if err != nil {
		return err
	}
	if populated && pendingMajor(version) {
		return fmt.Errorf("major database migration pending: stop Autentico and run autentico migrate; automatic upgrade is disabled")
	}
	return nil
}

// RecoveryPending prevents the server from using a partially completed upgrade.
func RecoveryPending(path string) error {
	path, err := dbguard.Path(path)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path + ".migration.json"); err == nil {
		return fmt.Errorf("interrupted major migration: run autentico migrate to recover before starting")
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

// RunFile applies migrations while holding the offline lock. A major upgrade
// checkpoints WAL, closes SQLite, and durably copies the entire database before
// applying any pending migrations. Failure restores that snapshot with SQLite
// closed. The backup is retained on success and failure.
func RunFile(path string, verbose bool, approvedMajors ...int) error {
	// Validate before opening, checkpointing, recovering or backing up the DB.
	if err := totpsecret.ValidateKey(config.GetBootstrap().TotpEncryptionKey); err != nil {
		return err
	}
	path, err := dbguard.Path(path)
	if err != nil {
		return err
	}
	if path == ":memory:" {
		return fmt.Errorf("file migrations require a file-backed database")
	}
	lock, err := dbguard.Acquire(path, true)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := recoverFile(path); err != nil {
		return err
	}
	db, err := openFile(path, false)
	if err != nil {
		return err
	}
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()
	version, err := getUserVersion(db)
	if err != nil {
		return err
	}
	populated, err := hasSchema(db)
	if err != nil {
		return err
	}
	if version >= SchemaVersion || !populated || !pendingMajor(version) {
		if err := ValidateApprovals(approvedMajors); err != nil {
			return err
		}
		if version == SchemaVersion && version >= 17 {
			if err := validateEncryptedTotp(db); err != nil {
				return err
			}
		}
		return run(db, verbose, true)
	}
	if err := requireApprovals(MajorVersions(version), approvedMajors); err != nil {
		return err
	}
	var busy, log, checkpointed int
	if err := db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &checkpointed); err != nil {
		return fmt.Errorf("major migration checkpoint failed: %w", err)
	}
	if busy != 0 {
		return fmt.Errorf("major migration checkpoint is busy; stop all database users before migrating")
	}
	if err := db.Close(); err != nil {
		return fmt.Errorf("close before backup: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	backup, digest, err := copySnapshot(path, path+fmt.Sprintf(".pre-v%d-*.db", SchemaVersion), 0600, nil)
	if err != nil {
		return fmt.Errorf("major migration backup failed: %w", err)
	}
	state := recoveryState{Backup: filepath.Base(backup), SHA256: digest, Version: version, Mode: info.Mode().Perm(), Owner: ownerFromInfo(info)}
	if err := validateSnapshot(backup, state); err != nil {
		return fmt.Errorf("major migration backup verification failed: %w", err)
	}
	if err := writeState(path, state); err != nil {
		return fmt.Errorf("major migration recovery record failed: %w", err)
	}
	fmt.Printf("Major migration backup: %s\n", backup)
	db, err = openFile(path, false)
	if err == nil {
		err = run(db, verbose, true)
		if err == nil && version < 17 {
			// SQLite VACUUM §2: secure_delete cannot scrub historical free
			// pages retroactively. Rebuild after encryption, outside the
			// migration transaction, while recovery still protects the upgrade.
			if _, vacuumErr := db.Exec("VACUUM"); vacuumErr != nil {
				err = fmt.Errorf("remove historical plaintext after TOTP encryption: %w", vacuumErr)
			}
		}
		if err == nil {
			// Finish the upgrade with no WAL dependency before removing the
			// recovery record, including pages written by the rebuild.
			var busy, log, checkpointed int
			err = db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &checkpointed)
			if err == nil && busy != 0 {
				err = fmt.Errorf("post-migration checkpoint is busy")
			}
		}
		err = errors.Join(err, db.Close())
	}
	if err != nil {
		if restoreErr := recoverFile(path); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("automatic restoration failed; backup retained at %s: %w", backup, restoreErr))
		}
		return fmt.Errorf("migration failed; restored schema v%d from %s: %w", version, backup, err)
	}
	return clearState(path)
}

// RecoverFile restores an interrupted upgrade without applying migrations.
// The CLI then asks for approval again before making another upgrade attempt.
func RecoverFile(path string) error {
	path, err := dbguard.Path(path)
	if err != nil {
		return err
	}
	if err := RecoveryPending(path); err == nil {
		return nil
	}
	lock, err := dbguard.Acquire(path, true)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	return recoverFile(path)
}

func copySnapshot(source, pattern string, mode os.FileMode, owner *fileOwner) (name, digest string, err error) {
	in, err := os.Open(source)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = in.Close() }()
	out, err := os.CreateTemp(filepath.Dir(pattern), filepath.Base(pattern))
	if err != nil {
		return "", "", err
	}
	name = out.Name()
	defer func() {
		_ = out.Close()
		if err != nil {
			_ = os.Remove(name)
		}
	}()
	h := sha256.New()
	if _, err = io.Copy(io.MultiWriter(out, h), in); err != nil {
		return name, "", err
	}
	if err = setFileOwner(out, owner); err != nil {
		return name, "", err
	}
	if err = out.Chmod(mode); err != nil {
		return name, "", err
	}
	if err = out.Sync(); err != nil {
		return name, "", err
	}
	if err = out.Close(); err != nil {
		return name, "", err
	}
	if err = syncDirectory(filepath.Dir(name)); err != nil {
		return name, "", err
	}
	return name, hex.EncodeToString(h.Sum(nil)), nil
}

func validateSnapshot(path string, state recoveryState) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, file)
	err = errors.Join(copyErr, file.Close())
	if err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != state.SHA256 {
		return fmt.Errorf("backup checksum mismatch")
	}
	db, err := openFile(path, true)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	version, err := getUserVersion(db)
	if err != nil {
		return err
	}
	if version != state.Version {
		return fmt.Errorf("backup schema mismatch: got %d, expected %d", version, state.Version)
	}
	var check string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&check); err != nil {
		return err
	}
	if check != "ok" {
		return fmt.Errorf("backup integrity check: %s", check)
	}
	return nil
}

func writeState(path string, state recoveryState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".migration-*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	_, writeErr := file.Write(data)
	err = errors.Join(writeErr, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	// Publish only a complete, synced record. A short write must not leave a
	// malformed recovery record that prevents an otherwise safe retry.
	if _, err := os.Lstat(path + ".migration.json"); !os.IsNotExist(err) {
		if err != nil {
			return err
		}
		return fmt.Errorf("migration recovery record already exists")
	}
	if err := os.Rename(file.Name(), path+".migration.json"); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func clearState(path string) error {
	if err := os.Remove(path + ".migration.json"); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func recoverFile(path string) error {
	data, err := os.ReadFile(path + ".migration.json")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var state recoveryState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("invalid migration recovery record; manual recovery required: %w", err)
	}
	if state.Backup == "" || filepath.Base(state.Backup) != state.Backup {
		return fmt.Errorf("invalid backup path in migration recovery record")
	}
	backup := filepath.Join(filepath.Dir(path), state.Backup)
	if err := validateSnapshot(backup, state); err != nil {
		return fmt.Errorf("cannot restore migration backup %s: %w", backup, err)
	}
	staged, digest, err := copySnapshot(backup, path+".restore-*.tmp", state.Mode.Perm(), state.Owner)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(staged) }()
	if digest != state.SHA256 {
		return fmt.Errorf("restoration checksum mismatch")
	}
	// No SQLite connections may be open here. SQLite lockingv3 §4.1: a hot
	// rollback journal is replayed before reads, so neither it nor stale WAL
	// may accompany a replaced snapshot. The recovery record survives crashes.
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale %s: %w", suffix, err)
		}
	}
	if err := os.Rename(staged, path); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if err := clearState(path); err != nil {
		return err
	}
	fmt.Printf("Restored pre-migration database from %s\n", backup)
	return nil
}
