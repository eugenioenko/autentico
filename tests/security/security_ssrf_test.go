package security

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SSRF in federation provider registration tests.
//
// CVE-2020-10770 (Keycloak): SSRF via request_uri OIDC parameter
// CVE-2026-1180 (Keycloak): SSRF via jwks_uri in dynamic client registration
// Federation providers with internal/metadata URLs as issuer

// Federation provider with cloud metadata URL as issuer should be rejected
// or at minimum not trigger SSRF at creation time.
func TestFederation_SSRF_CloudMetadataIssuer(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "ssrf-admin", "password123", "ssrf@test.com")

	maliciousIssuers := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://100.100.100.200/latest/meta-data/",
		"http://[::ffff:169.254.169.254]/latest/",
	}

	for _, issuer := range maliciousIssuers {
		t.Run(issuer, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"name":          "malicious-provider",
				"issuer":        issuer,
				"client_id":     "c1",
				"client_secret": "s1",
				"enabled":       true,
			})

			req, err := http.NewRequest("POST", ts.BaseURL+"/admin/api/federation/providers",
				bytes.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+adminToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err := ts.Client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			// At minimum the creation should not trigger an outbound request.
			// Ideally it should reject internal URLs.
			// If it accepts (201/200), that's a finding — the URL is stored
			// and will be fetched when federation login is attempted.
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
				t.Logf("FINDING: server accepted SSRF-risky issuer %q (status %d) — "+
					"URL will be fetched during federation login", issuer, resp.StatusCode)
			}
		})
	}
}

// Federation provider with localhost/loopback issuer.
func TestFederation_SSRF_LoopbackIssuer(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "loop-admin", "password123", "loop@test.com")

	loopbackIssuers := []string{
		"http://127.0.0.1:8080",
		"http://localhost:8080",
		"http://[::1]:8080",
		"http://0.0.0.0:8080",
	}

	for _, issuer := range loopbackIssuers {
		t.Run(issuer, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"name":          "loopback-provider",
				"issuer":        issuer,
				"client_id":     "c1",
				"client_secret": "s1",
				"enabled":       true,
			})

			req, err := http.NewRequest("POST", ts.BaseURL+"/admin/api/federation/providers",
				bytes.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+adminToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err := ts.Client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
				t.Logf("FINDING: server accepted loopback issuer %q (status %d)", issuer, resp.StatusCode)
			}
		})
	}
}

// Federation provider with file:// or other dangerous schemes.
func TestFederation_SSRF_DangerousSchemes(t *testing.T) {
	ts := startTestServer(t)
	_, adminToken := createTestAdmin(t, ts, "scheme-admin", "password123", "scheme@test.com")

	schemes := []string{
		"file:///etc/passwd",
		"gopher://internal:25/",
		"dict://internal:11211/",
	}

	for _, issuer := range schemes {
		t.Run(issuer, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"name":          "scheme-provider",
				"issuer":        issuer,
				"client_id":     "c1",
				"client_secret": "s1",
				"enabled":       true,
			})

			req, err := http.NewRequest("POST", ts.BaseURL+"/admin/api/federation/providers",
				bytes.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+adminToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err := ts.Client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			// These should be rejected — non-HTTP schemes make no sense for OIDC
			assert.NotEqual(t, http.StatusOK, resp.StatusCode,
				"non-HTTP scheme issuer %q should be rejected", issuer)
			assert.NotEqual(t, http.StatusCreated, resp.StatusCode,
				"non-HTTP scheme issuer %q should be rejected", issuer)
		})
	}
}
