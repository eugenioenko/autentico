package introspect

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/key"
	"github.com/eugenioenko/autentico/pkg/utils"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// RFC 7662 §2.2 / RFC 7519 §4.1.3, §4.1.7: optional claims describe
// the presented credential, not its paired token or current configuration.
func TestIntrospectionUsesPresentedAudienceAndID(t *testing.T) {
	for _, credential := range []string{"access", "refresh"} {
		for _, tc := range []struct {
			name             string
			audience         any
			id               any
			opaque           bool
			expectedAudience any
			expectedID       any
		}{
			{name: "multiple audiences", audience: []string{"original-issuer", testClientID, "per-client-resource"}, id: "original-jti", expectedAudience: []any{"original-issuer", testClientID, "per-client-resource"}, expectedID: "original-jti"},
			{name: "single audience", audience: "resource", id: "single-jti", expectedAudience: []any{"resource"}, expectedID: "single-jti"},
			{name: "absent claims"},
			{name: "invalid audience keeps valid id", audience: 42, id: "valid-jti", expectedID: "valid-jti"},
			{name: "invalid id keeps valid audience", audience: "resource", id: 42, expectedAudience: []any{"resource"}},
			{name: "mixed audience array", audience: []any{"resource", 42}},
			{name: "empty claims", audience: []string{}, id: ""},
			{name: "invalid claim types", audience: 42, id: 42},
			{name: "opaque credential", opaque: true},
		} {
			t.Run(credential+"/"+tc.name, func(t *testing.T) {
				testutils.WithTestDB(t)
				setupTestClient(t)
				testutils.InsertTestUser(t, "claims-user")
				access, _, err := generateTestTokenAndStore("claims-user")
				require.NoError(t, err)
				claims := jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}
				if tc.audience != nil {
					claims["aud"] = tc.audience
				}
				if tc.id != nil {
					claims["jti"] = tc.id
				}
				presented, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key.GetPrivateKey())
				require.NoError(t, err)
				if tc.opaque {
					presented = "opaque-credential"
				}
				if credential == "access" {
					_, err = db.GetDB().Exec("UPDATE tokens SET access_token_hash=?", utils.HashToken(presented))
					require.NoError(t, err)
					_, err = db.GetDB().Exec("UPDATE sessions SET access_token_hash=? WHERE access_token_hash=?", utils.HashToken(presented), utils.HashToken(access))
				} else {
					_, err = db.GetDB().Exec("UPDATE tokens SET refresh_token_hash=?", utils.HashToken(presented))
				}
				require.NoError(t, err)
				// Changing runtime audiences must not rewrite issued credentials' metadata.
				testutils.WithConfigOverride(t, func() {
					config.Values.AuthAccessTokenAudience = []string{"new-global-resource"}
				})
				req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(url.Values{"token": {presented}}.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				withBasicAuth(req)
				rr := httptest.NewRecorder()
				HandleIntrospect(rr, req)
				require.Equal(t, http.StatusOK, rr.Code)
				var response map[string]any
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
				require.Equal(t, true, response["active"])
				if tc.expectedAudience == nil {
					require.NotContains(t, response, "aud")
				} else {
					require.Equal(t, tc.expectedAudience, response["aud"])
				}
				if tc.expectedID == nil {
					require.NotContains(t, response, "jti")
				} else {
					require.Equal(t, tc.expectedID, response["jti"])
				}
			})
		}
	}
}

func TestIntrospectionDoesNotTrustUnstoredOrAlteredClaims(t *testing.T) {
	testutils.WithTestDB(t)
	setupTestClient(t)
	testutils.InsertTestUser(t, "claims-user")
	stored, _, err := generateTestTokenAndStore("claims-user")
	require.NoError(t, err)
	claims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(stored, claims)
	require.NoError(t, err)
	claims["aud"] = []string{"attacker-resource"}
	claims["jti"] = "attacker-jti"
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("attacker-key"))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(url.Values{"token": {forged}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	withBasicAuth(req)
	rr := httptest.NewRecorder()
	HandleIntrospect(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	require.JSONEq(t, `{"active":false}`, rr.Body.String())
}
