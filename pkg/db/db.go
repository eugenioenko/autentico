package db

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite" // Import SQLite driver
)

var db *sql.DB

// InitDB initializes the database connection and sets up the users table
func InitDB() (*sql.DB, error) {
	var err error
	db, err = sql.Open("sqlite", "./auth.db")
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
		return nil, err
	}

	// Create users table if not exists
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		email TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
		return nil, err
	}

	return db, nil
}

// GetDB returns the current database connection
func GetDB() *sql.DB {
	return db
}

// CloseDB closes the database connection
func CloseDB() {
	if err := db.Close(); err != nil {
		log.Printf("Failed to close database: %v", err)
	}
}
