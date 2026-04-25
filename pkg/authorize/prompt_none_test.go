package authorize

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/idpsession"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleAuthorize_PromptNone_NoSession_Extra(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost/cb"})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=c1&redirect_uri=http://localhost/cb&prompt=none&state=s1&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256", nil)
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// prompt=none with no session should redirect back with login_required error
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=login_required")
	assert.Contains(t, rr.Header().Get("Location"), "state=s1")
}

func TestHandleAuthorize_PromptNone_MaxAgeExpired_ReturnsLoginRequired(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestClient(t, "c1", []string{"http://localhost/cb"})
	testutils.WithConfigOverride(t, func() {
		config.Values.AuthSsoSessionIdleTimeout = 24 * time.Hour
		config.Values.AuthSsoSessionMaxAge = 1 * time.Hour
		config.Bootstrap.AuthIdpSessionCookieName = "autentico_idp_session"
	})

	_, err := db.GetDB().Exec(`INSERT INTO users (id, username, email, password) VALUES ('user-pn-1', 'pnuser', 'pn@test.com', 'hashed')`)
	require.NoError(t, err)

	require.NoError(t, idpsession.CreateIdpSession(idpsession.IdpSession{
		ID: "idp-pn-maxage", UserID: "user-pn-1", UserAgent: "ua", IPAddress: "127.0.0.1",
	}))
	// Backdate created_at to 2h ago — beyond 1h max age, but recently active
	_, err = db.GetDB().Exec(`UPDATE idp_sessions SET created_at = datetime('now', '-2 hours') WHERE id = 'idp-pn-maxage'`)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=c1&redirect_uri=http://localhost/cb&prompt=none&state=s2&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256", nil)
	req.AddCookie(&http.Cookie{Name: "autentico_idp_session", Value: "idp-pn-maxage"})
	rr := httptest.NewRecorder()

	HandleAuthorize(rr, req)

	// OIDC Core §3.1.2.6: prompt=none must not show UI; expired session must return login_required
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "error=login_required")
	assert.Contains(t, rr.Header().Get("Location"), "state=s2")
}
