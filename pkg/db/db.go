package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"runtime"

	"log/slog"

	_ "modernc.org/sqlite"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db/migrations"
)

var (
	writer  *sql.DB
	reader  *sql.DB
	pooledDB *DB
)

// DB routes read operations to the reader pool and write operations to the
// writer pool. Use GetDB() to obtain an instance.
type DB struct {
	writer *sql.DB
	reader *sql.DB
}

func (d *DB) Exec(query string, args ...any) (sql.Result, error) {
	return d.writer.Exec(query, args...)
}

func (d *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return d.writer.ExecContext(ctx, query, args...)
}

func (d *DB) Query(query string, args ...any) (*sql.Rows, error) {
	return d.reader.Query(query, args...)
}

func (d *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return d.reader.QueryContext(ctx, query, args...)
}

func (d *DB) QueryRow(query string, args ...any) *sql.Row {
	return d.reader.QueryRow(query, args...)
}

func (d *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return d.reader.QueryRowContext(ctx, query, args...)
}

func (d *DB) Begin() (*sql.Tx, error) {
	return d.writer.Begin()
}

func (d *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	return d.writer.BeginTx(ctx, opts)
}

func (d *DB) PingContext(ctx context.Context) error {
	return d.reader.PingContext(ctx)
}

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
		_, _ = conn.ExecContext(context.Background(), "PRAGMA busy_timeout = 5000;")
		_, _ = conn.ExecContext(context.Background(), "PRAGMA foreign_keys = ON;")
		conns[i] = conn
	}
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
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

	readPoolSize := config.GetBootstrap().DbReadPoolSize
	if readPoolSize <= 0 {
		readPoolSize = min(runtime.GOMAXPROCS(0), 4)
		if readPoolSize < 2 {
			readPoolSize = 2
		}
	}
	reader, err = openPool(dbFilePath, readPoolSize)
	if err != nil {
		return nil, err
	}

	pooledDB = &DB{writer: writer, reader: reader}

	log.Printf("SQLite pools: 1 writer, %d readers (WAL mode)", readPoolSize)

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
	pooledDB = &DB{writer: writer, reader: reader}

	if err = migrations.Run(writer, false); err != nil {
		log.Fatalf("Failed to initialize test database schema: %v", err)
		return nil, err
	}

	return writer, nil
}

// GetDB returns a DB that routes reads to the reader pool and writes to the
// writer pool automatically.
func GetDB() *DB {
	return pooledDB
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
