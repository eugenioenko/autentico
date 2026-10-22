package security

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestHTTPResetAndMfaRedemptionHaveOneWinner(t *testing.T) {
	for _, flow := range []string{"reset", "mfa"} {
		t.Run(flow, func(t *testing.T) {
			ts := startTestServer(t)
			usr := createTestUser(t, "http-race", "OldPassword123!", "http-race@example.com")
			path, query := "/oauth2/reset-password", url.Values{"token": {"http-reset-secret"}}
			if flow == "reset" {
				_, err := db.GetDB().Exec(`INSERT INTO password_reset_tokens(id,user_id,token_hash,expires_at)
					VALUES('http-reset',?,?,?)`, usr.ID, utils.HashSHA256("http-reset-secret"), time.Now().Add(time.Minute))
				require.NoError(t, err)
			} else {
				path, query = "/oauth2/mfa", url.Values{"challenge_id": {"http-mfa"}}
				require.NoError(t, mfa.CreateMfaChallenge(mfa.MfaChallenge{ID: "http-mfa", UserID: usr.ID, Method: "email",
					Code: utils.HashSHA256("123456"), ExpiresAt: time.Now().Add(time.Minute),
					LoginState: `{"client_id":"test-client","redirect_uri":"http://localhost:3000/callback","scope":"openid","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256"}`}))
				// Arrange an already-sent email, so loading the CSRF form uses
				// the resend cooldown instead of rotating our known OTP.
				_, err := db.GetDB().Exec(`UPDATE mfa_challenges SET otp_sent_at=CURRENT_TIMESTAMP WHERE id='http-mfa'`)
				require.NoError(t, err)
			}
			resp, err := ts.Client.Get(ts.BaseURL + path + "?" + query.Encode())
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, http.StatusOK, resp.StatusCode)
			csrfToken := getCSRFToken(string(body))
			require.NotEmpty(t, csrfToken)
			type reply struct {
				status   int
				location string
				body     string
				err      error
			}
			results := make(chan reply, 20)
			start := make(chan struct{})
			for i := range cap(results) {
				go func() {
					<-start
					form := url.Values{"gorilla.csrf.Token": {csrfToken}}
					if flow == "reset" {
						password := fmt.Sprintf("HttpNewPassword%d!", i)
						form.Set("token", "http-reset-secret")
						form.Set("password", password)
						form.Set("confirm_password", password)
					} else {
						form.Set("challenge_id", "http-mfa")
						form.Set("code", "123456")
					}
					req, requestErr := http.NewRequest(http.MethodPost, ts.BaseURL+path, strings.NewReader(form.Encode()))
					if requestErr != nil {
						results <- reply{err: requestErr}
						return
					}
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					req.Header.Set("Referer", ts.BaseURL+path)
					response, requestErr := ts.Client.Do(req)
					if requestErr != nil {
						results <- reply{err: requestErr}
						return
					}
					body, readErr := io.ReadAll(response.Body)
					_ = response.Body.Close()
					results <- reply{status: response.StatusCode, location: response.Header.Get("Location"), body: string(body), err: readErr}
				}()
			}
			close(start)
			winners := 0
			for range cap(results) {
				result := <-results
				require.NoError(t, result.err)
				require.NotEqual(t, http.StatusForbidden, result.status, "requests must reach the CSRF-protected handler")
				if (flow == "reset" && strings.Contains(result.body, "reset successfully")) ||
					(flow == "mfa" && strings.HasPrefix(result.location, "http://localhost:3000/callback")) {
					winners++
				}
			}
			require.Equal(t, 1, winners)
			if flow == "mfa" {
				var codes int
				require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM auth_codes WHERE user_id=?`, usr.ID).Scan(&codes))
				require.Equal(t, 1, codes)
			}
		})
	}
}
