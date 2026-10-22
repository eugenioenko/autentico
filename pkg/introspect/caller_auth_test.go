package introspect

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/utils"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestIntrospectionRejectsPublicClientCredentials(t *testing.T) {
	for _, auth := range []string{"form", "basic", "form with secret"} {
		t.Run(auth, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestClient(t, "public-client", []string{"http://localhost/cb"})
			form := url.Values{"token": {"unknown-token"}}
			if auth != "basic" {
				form.Set("client_id", "public-client")
			}
			if auth == "form with secret" {
				form.Set("client_secret", "made-up-secret")
			}
			req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if auth == "basic" {
				req.SetBasicAuth("public-client", "made-up-secret")
			}
			rr := httptest.NewRecorder()
			HandleIntrospect(rr, req)
			require.Equal(t, http.StatusUnauthorized, rr.Code)
			require.Equal(t, `Basic realm="introspection"`, rr.Header().Get("WWW-Authenticate"))
			require.Contains(t, rr.Body.String(), "invalid_client")
			require.NotContains(t, rr.Body.String(), `"active"`)
		})
	}
}

func TestIntrospectionAdminBearerRequiresAdminAudience(t *testing.T) {
	for _, audience := range []string{"relying-party", config.AdminClientID} {
		t.Run(audience, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestUser(t, "admin-user")
			_, err := db.GetDB().Exec(`UPDATE users SET role='admin' WHERE id='admin-user'`)
			require.NoError(t, err)
			bearer := generateBearerJWT(t, "admin-user", audience)
			// Introspect the real active credential so a mistaken acceptance is visible.
			form := url.Values{"token": {bearer}}
			req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Authorization", "Bearer "+bearer)
			rr := httptest.NewRecorder()
			HandleIntrospect(rr, req)
			if audience != config.AdminClientID {
				require.Equal(t, http.StatusForbidden, rr.Code)
				require.Contains(t, rr.Header().Get("WWW-Authenticate"), `Bearer error="insufficient_scope"`)
				require.Contains(t, rr.Body.String(), "insufficient_scope")
				require.NotContains(t, rr.Body.String(), `"active"`)
			} else {
				require.Equal(t, http.StatusOK, rr.Code)
				var response IntrospectResponse
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
				require.True(t, response.Active)
			}
		})
	}
}

// RFC 7662 §2.1 / §4: authorization uses the caller's current stored state,
// independently of the active target token whose metadata would be disclosed.
func TestIntrospectionRejectsInvalidatedAdminCaller(t *testing.T) {
	for _, change := range []struct {
		name, query string
		status      int
		code        string
	}{
		{"revoked credential", `UPDATE tokens SET revoked_at=CURRENT_TIMESTAMP WHERE access_token_hash=?`, http.StatusUnauthorized, "invalid_token"},
		{"demoted admin", `UPDATE users SET role='user' WHERE id=?`, http.StatusForbidden, "insufficient_scope"},
		{"deactivated admin", `UPDATE users SET deactivated_at=CURRENT_TIMESTAMP WHERE id=?`, http.StatusForbidden, "insufficient_scope"},
	} {
		t.Run(change.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestUser(t, "caller")
			testutils.InsertTestUser(t, "target")
			_, err := db.GetDB().Exec(`UPDATE users SET role='admin' WHERE id='caller'`)
			require.NoError(t, err)
			caller := generateBearerJWT(t, "caller")
			target := generateBearerJWT(t, "target")
			argument := "caller"
			if change.name == "revoked credential" {
				argument = utils.HashToken(caller)
			}
			_, err = db.GetDB().Exec(change.query, argument)
			require.NoError(t, err)
			// Neither the caller's session nor the independent target was revoked.
			var activeSessions int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM sessions WHERE deactivated_at IS NULL`).Scan(&activeSessions))
			require.Equal(t, 2, activeSessions)
			_, err = IntrospectToken(target)
			require.NoError(t, err)
			form := url.Values{"token": {target}}
			req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Authorization", "Bearer "+caller)
			rr := httptest.NewRecorder()
			HandleIntrospect(rr, req)
			require.Equal(t, change.status, rr.Code)
			require.Contains(t, rr.Header().Get("WWW-Authenticate"), "Bearer")
			require.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="`+change.code+`"`)
			require.Contains(t, rr.Body.String(), change.code)
			require.NotContains(t, rr.Body.String(), `"active"`)
		})
	}
}
