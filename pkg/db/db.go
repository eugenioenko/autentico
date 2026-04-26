package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"runtime"

	_ "modernc.org/sqlite"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db/migrations"
)

var (
	writer *sql.DB
	reader *sql.DB
)

func openPool(dbFilePath string, maxConns int) (*sql.DB, error) {
	database, err := sql.Open("sqlite", dbFilePath)
	if err != nil {
		return nil, err
	}

	database.SetMaxOpenConns(maxConns)

	if config.GetBootstrap().DbWalMode {
		if _, err = database.Exec("PRAGMA journal_mode = WAL;"); err != nil {
			slog.Warn("failed to enable WAL journal mode", "error", err)
		}
	} else {
		if _, err = database.Exec("PRAGMA journal_mode = DELETE;"); err != nil {
			slog.Warn("failed to set DELETE journal mode", "error", err)
		}
	}

	if _, err = database.Exec("PRAGMA busy_timeout = 5000;"); err != nil {
		return nil, fmt.Errorf("failed to set SQLite busy timeout: %w", err)
	}

	if _, err = database.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		return nil, fmt.Errorf("failed to enable SQLite foreign keys: %w", err)
	}

	// Warm up all connections so every pooled conn has PRAGMAs set.
	conns := make([]*sql.Conn, maxConns)
	for i := range conns {
		conn, err := database.Conn(context.Background())
		if err != nil {
			break
		}
		conn.ExecContext(context.Background(), "PRAGMA busy_timeout = 5000;")
		conn.ExecContext(context.Background(), "PRAGMA foreign_keys = ON;")
		conns[i] = conn
	}
	for _, conn := range conns {
		if conn != nil {
			conn.Close()
		}
	}

	return database, nil
}

func InitDB(dbFilePath string) (*sql.DB, error) {
	var err error

	writer, err = openPool(dbFilePath, 1)
	if err != nil {
		return nil, err
	}

	n := runtime.NumCPU()
	if n < 4 {
		n = 4
	}
	reader, err = openPool(dbFilePath, n)
	if err != nil {
		return nil, err
	}

	var userVersion int
	if err = writer.QueryRow("PRAGMA user_version").Scan(&userVersion); err != nil {
		return nil, fmt.Errorf("failed to read schema version: %w", err)
	}

	if userVersion == 0 {
		if err = migrations.Run(writer, false); err != nil {
			return nil, fmt.Errorf("failed to initialize database schema: %w", err)
		}
	}

	return writer, nil
}

func InitTestDB() (*sql.DB, error) {
	var err error
	writer, err = openPool(":memory:", 1)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
		return nil, err
	}

	// In-memory DBs can't share across connections; reader = writer.
	reader = writer

	if err = migrations.Run(writer, false); err != nil {
		log.Fatalf("Failed to initialize test database schema: %v", err)
		return nil, err
	}

	return writer, nil
}

// GetDB returns the writer pool. Alias for GetWriteDB.
func GetDB() *sql.DB {
	return writer
}

func GetWriteDB() *sql.DB {
	return writer
}

func GetReadDB() *sql.DB {
	return reader
}

func CloseDB() {
	if reader != nil && reader != writer {
		if err := reader.Close(); err != nil {
			log.Printf("Failed to close reader database: %v", err)
		}
	}
	if writer != nil {
		if err := writer.Close(); err != nil {
			log.Printf("Failed to close writer database: %v", err)
		}
	}
}
