// Package dbguard coordinates database users with offline migrations.
package dbguard

import (
	"fmt"
	"os"
	"path/filepath"
)

type Lock struct{ file *os.File }

// Path resolves aliases so the server and migrator use the same lock file.
func Path(path string) (string, error) {
	if path == ":memory:" {
		return path, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if os.IsNotExist(err) {
		parent, parentErr := filepath.EvalSymlinks(filepath.Dir(abs))
		if parentErr != nil {
			return "", parentErr
		}
		return filepath.Join(parent, filepath.Base(abs)), nil
	}
	return resolved, err
}

// Acquire is nonblocking. Database users hold a shared lock for their lifetime;
// migrations hold an exclusive lock through checkpoint, backup, and recovery.
// Older binaries and external SQLite tools do not honor this advisory lock.
func Acquire(path string, exclusive bool) (*Lock, error) {
	if path == ":memory:" {
		return &Lock{}, nil
	}
	file, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("database lock: %w", err)
	}
	if err := lock(file, exclusive); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("database is in use; stop all Autentico instances before migrating: %w", err)
	}
	return &Lock{file: file}, nil
}

func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := unlock(l.file)
	closeErr := l.file.Close()
	l.file = nil
	if err != nil {
		return err
	}
	return closeErr
}
