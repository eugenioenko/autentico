package magiclink

import (
	"net/http"
	"net/http/httptest"
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestInvalidAuthorizationDoesNotConsumeMagicLink(t *testing.T) {
	for _, typed := range []bool{false, true} {
		t.Run(map[bool]string{false: "link", true: "typed code"}[typed], func(t *testing.T) {
			form, raw, hash := newCodeChallenge(t)
			form.Set("redirect_uri", "https://attacker.example/steal")
			testutils.SetAuthorizeSig(form)
			var rr *httptest.ResponseRecorder
			if typed {
				rr = verifyCodeRequest(form)
			} else {
				form.Set("token", raw)
				rr = httptest.NewRecorder()
				HandleMagicLinkVerify(rr, httptest.NewRequest(http.MethodGet, "/oauth2/magic-link/verify?"+form.Encode(), nil))
			}
			require.Equal(t, http.StatusBadRequest, rr.Code)
			_, _, used, err := getMagicLinkTokenInfo(hash)
			require.NoError(t, err)
			require.Nil(t, used)
			// The legitimate signed request can still redeem the same credential.
			form.Set("redirect_uri", "http://localhost:3000/callback")
			testutils.SetAuthorizeSig(form)
			if typed {
				rr = verifyCodeRequest(form)
			} else {
				rr = httptest.NewRecorder()
				HandleMagicLinkVerify(rr, httptest.NewRequest(http.MethodGet, "/oauth2/magic-link/verify?"+form.Encode(), nil))
			}
			require.Equal(t, http.StatusFound, rr.Code)
			_, _, used, err = getMagicLinkTokenInfo(hash)
			require.NoError(t, err)
			require.NotNil(t, used)
		})
	}
}
