package introspect

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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
