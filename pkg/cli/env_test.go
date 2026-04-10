package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildEnvContent_Production(t *testing.T) {
	content := buildEnvContent(envParams{
		appURL:        "https://auth.example.com",
		listenPort:    "443",
		accessSecret:  "access-secret-hex",
		refreshSecret: "refresh-secret-hex",
		csrfSecret:    "csrf-secret-hex",
		privateKeyB64: "base64-key-data",
		dev:           false,
	})

	assert.Contains(t, content, "AUTENTICO_APP_URL=https://auth.example.com")
	assert.Contains(t, content, "AUTENTICO_LISTEN_PORT=443")
	assert.Contains(t, content, "AUTENTICO_ACCESS_TOKEN_SECRET=access-secret-hex")
	assert.Contains(t, content, "AUTENTICO_REFRESH_TOKEN_SECRET=refresh-secret-hex")
	assert.Contains(t, content, "AUTENTICO_CSRF_SECRET_KEY=csrf-secret-hex")
	assert.Contains(t, content, "AUTENTICO_PRIVATE_KEY=base64-key-data")
	assert.Contains(t, content, "AUTENTICO_CSRF_SECURE_COOKIE=true")
	assert.Contains(t, content, "AUTENTICO_IDP_SESSION_SECURE=true")
	assert.NotContains(t, content, "development mode")
}

func TestBuildEnvContent_DevMode(t *testing.T) {
	content := buildEnvContent(envParams{
		appURL:        "http://localhost:9999",
		listenPort:    "9999",
		accessSecret:  "dev-access",
		refreshSecret: "dev-refresh",
		csrfSecret:    "dev-csrf",
		privateKeyB64: "dev-key",
		dev:           true,
	})

	assert.Contains(t, content, "AUTENTICO_APP_URL=http://localhost:9999")
	assert.Contains(t, content, "AUTENTICO_CSRF_SECURE_COOKIE=false")
	assert.Contains(t, content, "AUTENTICO_IDP_SESSION_SECURE=false")
	assert.Contains(t, content, "development mode")
	assert.NotContains(t, content, "AUTENTICO_CSRF_SECURE_COOKIE=true")
}

func TestBuildEnvContent_ContainsAllRequiredKeys(t *testing.T) {
	content := buildEnvContent(envParams{
		appURL:        "http://localhost:9999",
		listenPort:    "9999",
		accessSecret:  "a",
		refreshSecret: "b",
		csrfSecret:    "c",
		privateKeyB64: "d",
	})

	requiredKeys := []string{
		"AUTENTICO_DB_FILE_PATH",
		"AUTENTICO_APP_URL",
		"AUTENTICO_APP_OAUTH_PATH",
		"AUTENTICO_LISTEN_PORT",
		"AUTENTICO_ACCESS_TOKEN_SECRET",
		"AUTENTICO_REFRESH_TOKEN_SECRET",
		"AUTENTICO_CSRF_SECRET_KEY",
		"AUTENTICO_PRIVATE_KEY",
		"AUTENTICO_JWK_CERT_KEY_ID",
		"AUTENTICO_CSRF_SECURE_COOKIE",
		"AUTENTICO_REFRESH_TOKEN_COOKIE_NAME",
		"AUTENTICO_REFRESH_TOKEN_COOKIE_ONLY",
		"AUTENTICO_IDP_SESSION_COOKIE_NAME",
		"AUTENTICO_IDP_SESSION_SECURE",
		"AUTENTICO_RATE_LIMIT_RPS",
		"AUTENTICO_RATE_LIMIT_BURST",
		"AUTENTICO_RATE_LIMIT_RPM",
		"AUTENTICO_RATE_LIMIT_RPM_BURST",
		"AUTENTICO_ANTI_TIMING_MIN_MS",
		"AUTENTICO_ANTI_TIMING_MAX_MS",
	}

	for _, key := range requiredKeys {
		assert.Contains(t, content, key, "missing required key: %s", key)
	}
}

func TestBuildEnvContent_EndsWithNewline(t *testing.T) {
	content := buildEnvContent(envParams{
		appURL:        "http://localhost:9999",
		listenPort:    "9999",
		accessSecret:  "a",
		refreshSecret: "b",
		csrfSecret:    "c",
		privateKeyB64: "d",
	})

	assert.True(t, content[len(content)-1] == '\n')
}
