package db

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"

	"github.com/eugenioenko/autentico/pkg/db/migrations"
)

var db *sql.DB

func openDB(dbFilePath string) (*sql.DB, error) {
	database, err := sql.Open("sqlite", dbFilePath)
	if err != nil {
		return nil, err
	}

	// SQLite is single-writer; one connection avoids "database is locked" races
	// and ensures PRAGMAs set below apply to every query.
	database.SetMaxOpenConns(1)

	if _, err = database.Exec("PRAGMA busy_timeout = 5000;"); err != nil {
		panic("Failed to set SQLite busy timeout: " + err.Error())
	}

	if _, err = database.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		panic("Failed to enable SQLite foreign keys: " + err.Error())
	}

	return database, nil
}

func InitDB(dbFilePath string) (*sql.DB, error) {
	var err error
	db, err = openDB(dbFilePath)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
		return nil, err
	}

	var userVersion int
	if err = db.QueryRow("PRAGMA user_version").Scan(&userVersion); err != nil {
		log.Fatalf("Failed to read user_version: %v", err)
		return nil, err
	}

	// Fresh database — run all migrations to build the schema from scratch.
	if userVersion == 0 {
		if err = migrations.Run(db); err != nil {
			log.Fatalf("Failed to initialize database schema: %v", err)
			return nil, err
		}
	}

	return db, nil
}

func InitTestDB() (*sql.DB, error) {
	var err error
	db, err = openDB(":memory:")
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
		return nil, err
	}

	if err = migrations.Run(db); err != nil {
		log.Fatalf("Failed to initialize test database schema: %v", err)
		return nil, err
	}

	return db, nil
}

func GetDB() *sql.DB {
	return db
}

func CloseDB() {
	if err := db.Close(); err != nil {
		log.Printf("Failed to close database: %v", err)
	}
}
