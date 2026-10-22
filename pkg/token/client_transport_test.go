package token

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestRejectedClientTransportsDoNotIssueTokens(t *testing.T) {
	for _, kind := range []string{"URI credentials", "multiple mechanisms", "different body identity", "malformed Basic"} {
		t.Run(kind, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestConfidentialClient(t, "transport-client", "transport-secret")
			_, err := db.GetDB().Exec(`UPDATE clients SET grant_types='["client_credentials"]' WHERE client_id='transport-client'`)
			require.NoError(t, err)
			form := url.Values{"grant_type": {"client_credentials"}, "scope": {"profile"}}
			target := "/oauth2/token"
			if kind == "URI credentials" {
				target += "?" + url.Values{"client_id": {"transport-client"}, "client_secret": {"transport-secret"}}.Encode()
			} else {
				form.Set("client_id", "transport-client")
				if kind == "different body identity" {
					form.Set("client_id", "other-client")
				} else {
					form.Set("client_secret", "transport-secret")
				}
			}
			r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if kind == "multiple mechanisms" || kind == "different body identity" {
				r.SetBasicAuth("transport-client", "transport-secret")
			}
			status := http.StatusBadRequest
			code := "invalid_request"
			if kind == "malformed Basic" {
				r.Header.Set("Authorization", "Basic invalid-base64")
				status = http.StatusUnauthorized
				code = "invalid_client"
			}
			rr := httptest.NewRecorder()
			HandleToken(rr, r)
			require.Equal(t, status, rr.Code, rr.Body.String())
			require.Contains(t, rr.Body.String(), code)
			if status == http.StatusUnauthorized {
				require.Equal(t, `Basic realm="token"`, rr.Header().Get("WWW-Authenticate"))
			}
			var count int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&count))
			require.Zero(t, count)
		})
	}
}
