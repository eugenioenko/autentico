package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestOAuthBasicCredentialsDecodeExactlyOnce(t *testing.T) {
	testutils.WithTestDB(t)
	id, secret := "client:+%2B space é", "secret:+%2B space é"
	testutils.InsertTestConfidentialClient(t, id, secret)
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
	r.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	authenticated, err := AuthenticateClientFromRequest(r)
	require.NoError(t, err)
	require.NotNil(t, authenticated)
	require.Equal(t, id, authenticated.ClientID)
}

func TestAuthenticationRejectsUnsupportedOrAmbiguousCredentialTransports(t *testing.T) {
	for _, kind := range []string{"URL credentials", "URL secret with valid body", "URL public ID", "duplicate ID", "duplicate secret", "two auth headers", "Basic and form secret", "Basic and different body ID", "malformed Basic with valid form", "Bearer and form credentials", "invalid encoded Basic ID", "invalid encoded Basic secret"} {
		t.Run(kind, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestConfidentialClient(t, "transport-client", "transport-secret")
			form := url.Values{"client_id": {"transport-client"}, "client_secret": {"transport-secret"}}
			query := url.Values{}
			switch kind {
			case "URL credentials":
				query = form
				form = url.Values{}
			case "URL secret with valid body":
				query.Set("client_secret", "transport-secret")
			case "URL public ID":
				query.Set("client_id", "transport-client")
				form = url.Values{}
			case "duplicate ID":
				form.Add("client_id", "transport-client")
			case "duplicate secret":
				form.Add("client_secret", "transport-secret")
			case "Basic and different body ID":
				form.Set("client_id", "other-client")
				form.Del("client_secret")
			case "invalid encoded Basic ID", "invalid encoded Basic secret":
				form = url.Values{}
			}
			r := httptest.NewRequest(http.MethodPost, "/oauth2/token?"+query.Encode(), strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			switch kind {
			case "Basic and form secret", "Basic and different body ID":
				r.SetBasicAuth("transport-client", "transport-secret")
			case "malformed Basic with valid form":
				r.Header.Set("Authorization", "Basic invalid-base64")
			case "Bearer and form credentials":
				r.Header.Set("Authorization", "Bearer another-credential")
			case "two auth headers":
				r.SetBasicAuth("transport-client", "transport-secret")
				r.Header.Add("Authorization", r.Header.Get("Authorization"))
			case "invalid encoded Basic ID":
				r.SetBasicAuth("transport%ZZ", "transport-secret")
			case "invalid encoded Basic secret":
				r.SetBasicAuth("transport-client", "secret%ZZ")
			}
			authenticated, err := AuthenticateClientFromRequest(r)
			require.Error(t, err)
			require.Nil(t, authenticated)
		})
	}
}

func TestBasicMayRepeatOnlyItsOwnBodyClientID(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestConfidentialClient(t, "same+client", "same+secret")
	form := url.Values{"client_id": {"same+client"}}
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(url.QueryEscape("same+client"), url.QueryEscape("same+secret"))
	authenticated, err := AuthenticateClientFromRequest(r)
	require.NoError(t, err)
	require.Equal(t, "same+client", authenticated.ClientID)
}

func TestAuthenticationPreservesLegacyIntrospectionJSONBody(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestConfidentialClient(t, "json-client", "json-secret")
	body := `{"token":"the-target-token"}`
	r := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetBasicAuth("json-client", "json-secret")
	authenticated, err := AuthenticateClientFromRequest(r)
	require.NoError(t, err)
	require.NotNil(t, authenticated)
	remaining, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	require.Equal(t, body, string(remaining))
}
