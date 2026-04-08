package e2e

import (
	"net/http"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- CORS integration tests ------------------------------------------------
// These verify the full chain: runtime config → CORS middleware → response headers.

func TestCORS_Disabled_NoHeaders(t *testing.T) {
	ts := startTestServer(t)
	saved := config.Values
	t.Cleanup(func() { config.Values = saved })

	config.Values.CORSAllowedOrigins = nil
	config.Values.CORSAllowAll = false

	req, _ := http.NewRequest("GET", ts.BaseURL+"/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://app.example.com")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"), "no CORS headers when disabled")
}

func TestCORS_Wildcard(t *testing.T) {
	ts := startTestServer(t)
	saved := config.Values
	t.Cleanup(func() { config.Values = saved })

	config.Values.CORSAllowedOrigins = []string{"*"}
	config.Values.CORSAllowAll = true

	req, _ := http.NewRequest("GET", ts.BaseURL+"/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://anything.example.com")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, POST, PUT, DELETE, OPTIONS", resp.Header.Get("Access-Control-Allow-Methods"))
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Credentials"), "credentials not set for wildcard")
}

func TestCORS_SpecificOrigin_Allowed(t *testing.T) {
	ts := startTestServer(t)
	saved := config.Values
	t.Cleanup(func() { config.Values = saved })

	config.Values.CORSAllowedOrigins = []string{"https://app.example.com", "https://admin.example.com"}
	config.Values.CORSAllowAll = false

	req, _ := http.NewRequest("GET", ts.BaseURL+"/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://app.example.com")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, "https://app.example.com", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
	assert.Contains(t, resp.Header.Get("Vary"), "Origin")
}

func TestCORS_SpecificOrigin_SecondOriginAllowed(t *testing.T) {
	ts := startTestServer(t)
	saved := config.Values
	t.Cleanup(func() { config.Values = saved })

	config.Values.CORSAllowedOrigins = []string{"https://app.example.com", "https://admin.example.com"}
	config.Values.CORSAllowAll = false

	req, _ := http.NewRequest("GET", ts.BaseURL+"/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://admin.example.com")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, "https://admin.example.com", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
}

func TestCORS_SpecificOrigin_Rejected(t *testing.T) {
	ts := startTestServer(t)
	saved := config.Values
	t.Cleanup(func() { config.Values = saved })

	config.Values.CORSAllowedOrigins = []string{"https://app.example.com"}
	config.Values.CORSAllowAll = false

	req, _ := http.NewRequest("GET", ts.BaseURL+"/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://evil.com")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"), "rejected origin gets no CORS headers")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "request still succeeds, just without CORS headers")
}

func TestCORS_PreflightOptions_Wildcard(t *testing.T) {
	ts := startTestServer(t)
	saved := config.Values
	t.Cleanup(func() { config.Values = saved })

	config.Values.CORSAllowedOrigins = []string{"*"}
	config.Values.CORSAllowAll = true

	req, _ := http.NewRequest("OPTIONS", ts.BaseURL+"/oauth2/token", nil)
	req.Header.Set("Origin", "https://spa.example.com")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "Content-Type, Authorization", resp.Header.Get("Access-Control-Allow-Headers"))
}

func TestCORS_PreflightOptions_SpecificOrigin(t *testing.T) {
	ts := startTestServer(t)
	saved := config.Values
	t.Cleanup(func() { config.Values = saved })

	config.Values.CORSAllowedOrigins = []string{"https://spa.example.com"}
	config.Values.CORSAllowAll = false

	req, _ := http.NewRequest("OPTIONS", ts.BaseURL+"/oauth2/token", nil)
	req.Header.Set("Origin", "https://spa.example.com")

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, "https://spa.example.com", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
	assert.Contains(t, resp.Header.Get("Vary"), "Origin")
}

func TestCORS_NoOriginHeader_NoHeaders(t *testing.T) {
	ts := startTestServer(t)
	saved := config.Values
	t.Cleanup(func() { config.Values = saved })

	config.Values.CORSAllowedOrigins = []string{"*"}
	config.Values.CORSAllowAll = true

	req, _ := http.NewRequest("GET", ts.BaseURL+"/.well-known/openid-configuration", nil)
	// No Origin header set

	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"), "no Origin header = no CORS response headers")
}
