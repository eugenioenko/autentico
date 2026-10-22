package token

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestTokenGrantErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		name         string
		grant        *string
		authenticate bool
		status       int
		code         string
	}{
		{"missing", nil, true, http.StatusBadRequest, "invalid_request"},
		{"empty", new(string), true, http.StatusBadRequest, "invalid_request"},
		{"unknown authenticated", stringValue("urn:example:custom"), true, http.StatusBadRequest, "unsupported_grant_type"},
		{"unknown anonymous", stringValue("urn:example:custom"), false, http.StatusBadRequest, "unsupported_grant_type"},
		{"case sensitive", stringValue("PASSWORD"), true, http.StatusBadRequest, "unsupported_grant_type"},
		{"known but disallowed", stringValue("password"), true, http.StatusBadRequest, "unauthorized_client"},
		{"known requires authentication", stringValue("client_credentials"), false, http.StatusUnauthorized, "invalid_client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			insertConfidentialClient(t, "grant-error-client", "grant-error-secret", `["client_credentials"]`)
			form := url.Values{}
			if tc.grant != nil {
				form.Set("grant_type", *tc.grant)
			}
			r := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.authenticate {
				r.SetBasicAuth("grant-error-client", "grant-error-secret")
			}
			rr := httptest.NewRecorder()
			HandleToken(rr, r)
			require.Equal(t, tc.status, rr.Code, rr.Body.String())
			var body struct {
				Error       string `json:"error"`
				AccessToken string `json:"access_token"`
			}
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			require.Equal(t, tc.code, body.Error)
			require.Empty(t, body.AccessToken)
			if tc.status == http.StatusUnauthorized {
				require.Equal(t, `Basic realm="token"`, rr.Header().Get("WWW-Authenticate"))
			}
			var count int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

func stringValue(value string) *string { return &value }
