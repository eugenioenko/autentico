package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// registerSSRFProvider hits the same authenticated route and required fields as production.
func registerSSRFProvider(t *testing.T, ts *TestServer, adminToken, id, issuer string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"id": id, "name": "SSRF fixture", "issuer": issuer, "client_id": "upstream-client", "client_secret": "secret", "enabled": true})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, ts.BaseURL+"/admin/api/federation", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "registration must succeed so the test reaches outbound discovery")
}

// TestFederationSSRFBlocksDiscovery checks both entry points without contacting private targets.
func TestFederationSSRFBlocksDiscovery(t *testing.T) {
	ts := startTestServer(t)
	_, admin := createTestAdmin(t, ts, "ssrf-admin", "password123", "ssrf@test.com")
	var requests atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "http://" + r.Host, "authorization_endpoint": "https://provider.example/auth", "token_endpoint": "http://" + r.Host + "/token", "jwks_uri": "http://" + r.Host + "/jwks"})
	}))
	defer trap.Close()
	issuers := []string{trap.URL, "http://localhost:" + fmt.Sprint(trap.Listener.Addr().(*net.TCPAddr).Port), "http://169.254.169.254/latest/meta-data", "http://100.100.100.200/latest/meta-data", "http://[::ffff:169.254.169.254]", "http://[::1]", "http://0.0.0.0", "http://[::]", "file:///etc/passwd", "gopher://internal:25"}
	for i, issuer := range issuers {
		t.Run(issuer, func(t *testing.T) {
			id := fmt.Sprintf("ssrf-%d", i)
			registerSSRFProvider(t, ts, admin, id, issuer)
			params := federationParams()
			signed, browser := storedFederationState(t, id, params)
			for _, path := range []string{"/oauth2/federation/" + id + "?" + params.Encode(), "/oauth2/federation/" + id + "/callback?" + url.Values{"state": {signed}, "code": {"upstream-code"}}.Encode()} {
				req, err := http.NewRequest(http.MethodGet, ts.BaseURL+path, nil)
				require.NoError(t, err)
				req.AddCookie(browser)
				resp, err := ts.Client.Do(req)
				require.NoError(t, err)
				_ = resp.Body.Close()
				require.Equal(t, http.StatusBadGateway, resp.StatusCode)
				require.Empty(t, resp.Header.Get("Location"))
				require.Empty(t, resp.Cookies())
			}
		})
	}
	require.Zero(t, requests.Load(), "blocked discovery must not make even the first HTTP request")
}
