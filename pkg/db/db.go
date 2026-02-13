package db

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
)

var db *sql.DB
var createTableSQL = `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,                     -- Unique user ID (UUID or other format)
		username TEXT UNIQUE NOT NULL,           -- User's unique username
		email TEXT UNIQUE NOT NULL,              -- User's email (enforce uniqueness)
		password TEXT NOT NULL,                  -- Hashed password
		role TEXT NOT NULL DEFAULT 'user',       -- User role (e.g., 'admin', 'user', 'moderator')
		two_factor_enabled BOOLEAN DEFAULT FALSE, -- If 2FA is enabled
		totp_secret TEXT NOT NULL DEFAULT '',      -- TOTP secret (base32 encoded)
		totp_verified BOOLEAN DEFAULT FALSE,       -- Whether user has completed TOTP enrollment
		last_login DATETIME,                     -- Timestamp of last successful login
		failed_login_attempts INTEGER DEFAULT 0, -- Failed login attempt counter
		locked_until DATETIME,                   -- If account is locked, store unlock time
		password_last_changed DATETIME DEFAULT CURRENT_TIMESTAMP, -- When password was last updated
		is_email_verified BOOLEAN DEFAULT FALSE, -- Whether email is verified
		email_verification_token TEXT,           -- Store token used for email verification
		email_verification_expires_at DATETIME,  -- Expiration time of the verification token
		deactivated_at DATETIME DEFAULT NULL,    -- If account is deactivated, store timestamp
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- Account creation timestamp
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- Last update timestamp
		CONSTRAINT unique_username UNIQUE (username),
		CONSTRAINT unique_email UNIQUE (email)
	);

	CREATE TABLE IF NOT EXISTS tokens (
		id TEXT PRIMARY KEY,                     -- Unique token ID
		user_id TEXT NOT NULL,                    -- The user to whom the token belongs
		access_token TEXT NOT NULL,               -- The actual access token (JWT or opaque token)
		refresh_token TEXT NOT NULL,              -- The refresh token used for refreshing access tokens
		access_token_type TEXT NOT NULL,          -- Type of access token (e.g., 'Bearer', 'JWT')
		refresh_token_expires_at DATETIME NOT NULL, -- Expiration time for the refresh token (if applicable)
		refresh_token_last_used_at DATETIME,      -- Tracks when the refresh token was last used
		access_token_expires_at DATETIME NOT NULL, -- Expiration time for the access token
		issued_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- When the token was issued
		scope TEXT NOT NULL,                          -- The scopes granted for this token (nullable)
		grant_type TEXT NOT NULL,                 -- The OAuth2 grant type (e.g., 'authorization_code', 'client_credentials')
		revoked_at DATETIME,                      -- Timestamp for when the token was revoked
		CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) -- Link to the user
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,                           -- Unique session ID
		user_id TEXT,                                  -- The user who owns the session
		access_token TEXT,                             -- The access token associated with the session
		refresh_token TEXT,                            -- (Optional) The refresh token associated with the session
		user_agent TEXT,                               -- The user agent string (browser, device info)
		ip_address TEXT,                               -- The IP address of the user when the session was created
		device_id TEXT,                                -- Unique identifier for the device (for multi-device support)
		location TEXT,                                 -- The location where the session was initiated
		last_activity_at DATETIME,                     -- Timestamp of the last activity in this session
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- When the session was created
		expires_at DATETIME,                           -- When the session will expire
		deactivated_at DATETIME,                       -- Timestamp when the session was deactivated or invalidated
		FOREIGN KEY (user_id) REFERENCES users(id)    -- Link to the user
	);

	CREATE TABLE IF NOT EXISTS auth_codes (
    code TEXT PRIMARY KEY,                    -- The actual authorization code
    user_id TEXT NOT NULL,                    -- The authenticated user
    client_id TEXT,                           -- The client that requested the code
    redirect_uri TEXT NOT NULL,               -- Must match the one used in the initial request
    scope TEXT,                               -- Scopes associated with this code
    nonce TEXT NOT NULL DEFAULT '',            -- OIDC nonce for ID token replay protection
    code_challenge TEXT NOT NULL DEFAULT '',   -- PKCE code challenge
    code_challenge_method TEXT NOT NULL DEFAULT '', -- PKCE method (S256 or plain)
    expires_at DATETIME NOT NULL,             -- Expiration time (typically short-lived)
    used BOOLEAN DEFAULT FALSE,               -- To prevent reuse
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS idp_sessions (
		id TEXT PRIMARY KEY,                                -- Unique session ID (cryptographic random)
		user_id TEXT NOT NULL,                              -- The authenticated user
		user_agent TEXT,                                    -- Browser/device info
		ip_address TEXT,                                    -- Client IP address
		last_activity_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- Last time session was used for auto-login
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,      -- When the session was created
		deactivated_at DATETIME,                            -- When the session was invalidated
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS mfa_challenges (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		method TEXT NOT NULL,
		code TEXT NOT NULL DEFAULT '',
		login_state TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		used BOOLEAN DEFAULT FALSE,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS clients (
		id TEXT PRIMARY KEY,                                          -- Internal unique ID
		client_id TEXT UNIQUE NOT NULL,                               -- Public client identifier
		client_secret TEXT,                                           -- Hashed secret (NULL for public clients)
		client_name TEXT NOT NULL,                                    -- Human-readable name
		client_type TEXT NOT NULL DEFAULT 'confidential',             -- 'confidential' or 'public'
		redirect_uris TEXT NOT NULL,                                  -- JSON array of allowed redirect URIs
		grant_types TEXT NOT NULL DEFAULT '["authorization_code"]',   -- JSON array of allowed grant types
		response_types TEXT NOT NULL DEFAULT '["code"]',              -- JSON array of allowed response types
		scopes TEXT NOT NULL DEFAULT 'openid profile email',          -- Space-separated allowed scopes
		token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic', -- Authentication method
		is_active BOOLEAN DEFAULT TRUE,                               -- Whether client is active
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,                -- Creation timestamp
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP                 -- Last update timestamp
	);
`

var dropTableSQL = `
		DROP TABLE IF EXISTS users;
		DROP TABLE IF EXISTS sessions;
		DROP TABLE IF EXISTS tokens;
		DROP TABLE IF EXISTS auth_codes;
		DROP TABLE IF EXISTS idp_sessions;
		DROP TABLE IF EXISTS mfa_challenges;
		DROP TABLE IF EXISTS clients;
	`

func InitDB(dbFilePath string) (*sql.DB, error) {
	var err error
	db, err = sql.Open("sqlite", dbFilePath)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
		return nil, err
	}

	_, err = db.Exec("PRAGMA busy_timeout = 5000;") // 5000ms timeout
	if err != nil {
		panic("Failed to set SQLite busy timeout: " + err.Error())
	}

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
		return nil, err
	}

	return db, nil
}

func InitTestDB() (*sql.DB, error) {
	dbFilePath := ":memory:"
	var err error
	db, err = sql.Open("sqlite", dbFilePath)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
		return nil, err
	}

	_, err = db.Exec("PRAGMA busy_timeout = 5000;") // 5000ms timeout
	if err != nil {
		panic("Failed to set SQLite busy timeout: " + err.Error())
	}

	_, err = db.Exec(dropTableSQL)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
		return nil, err
	}

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
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
