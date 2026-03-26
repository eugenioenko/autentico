package migrations

const migration001 = `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,                     -- Unique user ID (UUID or other format)
		username TEXT UNIQUE NOT NULL,           -- User's unique username
		email TEXT UNIQUE,                       -- User's email (optional, enforce uniqueness when present)
		password TEXT,                           -- Hashed password (NULL for passkey-only users)
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
		registered_at DATETIME DEFAULT NULL,     -- NULL only for passkey users mid-ceremony; set immediately for password users
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- Account creation timestamp
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- Last update timestamp
		-- OIDC standard profile claims
		given_name TEXT NOT NULL DEFAULT '',
		family_name TEXT NOT NULL DEFAULT '',
		middle_name TEXT NOT NULL DEFAULT '',
		nickname TEXT NOT NULL DEFAULT '',
		website TEXT NOT NULL DEFAULT '',
		gender TEXT NOT NULL DEFAULT '',
		birthdate TEXT NOT NULL DEFAULT '',
		profile TEXT NOT NULL DEFAULT '',
		phone_number TEXT NOT NULL DEFAULT '',
		phone_number_verified BOOLEAN DEFAULT FALSE,
		picture TEXT NOT NULL DEFAULT '',
		locale TEXT NOT NULL DEFAULT '',
		zoneinfo TEXT NOT NULL DEFAULT '',
		address_street TEXT NOT NULL DEFAULT '',
		address_locality TEXT NOT NULL DEFAULT '',
		address_region TEXT NOT NULL DEFAULT '',
		address_postal_code TEXT NOT NULL DEFAULT '',
		address_country TEXT NOT NULL DEFAULT '',
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
		failed_attempts INTEGER NOT NULL DEFAULT 0,
		otp_sent_at DATETIME,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS trusted_devices (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		device_name TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS passkey_challenges (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		challenge_data TEXT NOT NULL,
		type TEXT NOT NULL,
		login_state TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		used BOOLEAN DEFAULT FALSE,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS passkey_credentials (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL DEFAULT '',
		credential TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_used_at DATETIME,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,                -- Last update timestamp
		-- Per-client overrides (NULL = use global setting)
		access_token_expiration TEXT,
		refresh_token_expiration TEXT,
		authorization_code_expiration TEXT,
		allowed_audiences TEXT,
		allow_self_signup INTEGER,
		sso_session_idle_timeout TEXT,
		trust_device_enabled INTEGER,
		trust_device_expiration TEXT,
		post_logout_redirect_uris TEXT DEFAULT '[]'                   -- JSON array of allowed post-logout redirect URIs
	);

	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS federation_providers (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		issuer TEXT NOT NULL,
		client_id TEXT NOT NULL,
		client_secret TEXT NOT NULL,
		icon_svg TEXT,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		sort_order INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS federated_identities (
		id TEXT PRIMARY KEY,
		provider_id TEXT NOT NULL,
		provider_user_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		email TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (provider_id) REFERENCES federation_providers(id),
		FOREIGN KEY (user_id) REFERENCES users(id),
		UNIQUE(provider_id, provider_user_id)
	);

	CREATE TABLE IF NOT EXISTS deletion_requests (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		reason TEXT,
		requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE INDEX IF NOT EXISTS idx_tokens_refresh_token ON tokens(refresh_token);
	CREATE INDEX IF NOT EXISTS idx_tokens_access_token ON tokens(access_token);
	CREATE INDEX IF NOT EXISTS idx_sessions_access_token ON sessions(access_token);
	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_idp_sessions_user_id ON idp_sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_id ON passkey_credentials(user_id);
	CREATE INDEX IF NOT EXISTS idx_federated_identities_user_id ON federated_identities(user_id);
	CREATE INDEX IF NOT EXISTS idx_deletion_requests_user_id ON deletion_requests(user_id);
`
