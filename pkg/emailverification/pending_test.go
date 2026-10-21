package emailverification

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/eugenioenko/autentico/pkg/authzsig"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/require"
)

func TestPendingVerificationValidatesBeforeSigningAndRendering(t *testing.T) {
	withVerificationTestDB(t)
	p := OAuthParams{ClientID: "test-client", RedirectURI: "http://localhost/callback", CodeChallenge: "challenge", CodeChallengeMethod: "S256", State: "state & unicode é"}
	pending, err := PendingURL("does-not-exist", p)
	require.NoError(t, err)
	u, err := url.Parse(pending)
	require.NoError(t, err)
	require.Empty(t, u.Query().Get("token"))
	require.Equal(t, p.State, u.Query().Get("state"))
	require.True(t, authzsig.Verify(authzsig.FromValues(u.Query()), u.Query().Get("authorize_sig")))
	w := httptest.NewRecorder()
	HandlePendingVerification(w, httptest.NewRequest("GET", pending, nil))
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "resend-verification")
	q := u.Query()
	q.Set("redirect_uri", "https://attacker.example/steal")
	u.RawQuery = q.Encode()
	w = httptest.NewRecorder()
	HandlePendingVerification(w, httptest.NewRequest("GET", u.String(), nil))
	require.Equal(t, 400, w.Code)
	p.RedirectURI = "https://attacker.example/steal"
	_, err = PendingURL("victim", p)
	require.Error(t, err)
	_, err = db.GetDB().Exec("UPDATE clients SET is_active=FALSE WHERE client_id='test-client'")
	require.NoError(t, err)
	w = httptest.NewRecorder()
	HandlePendingVerification(w, httptest.NewRequest("GET", pending, nil))
	require.Equal(t, 400, w.Code, "even a genuine signature must recheck client registration")
}
