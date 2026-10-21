package emailverification

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func privacyResendRequest() *http.Request {
	form := url.Values{"username": {"resend-probe"}, "client_id": {"test-client"}, "redirect_uri": {"http://localhost/callback"}, "scope": {"openid"}}
	signVerificationParams(form)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/resend-verification", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestResendVerificationHasOnePublicResponse(t *testing.T) {
	var generic string
	for _, state := range []string{"unknown", "unverified", "verified", "no email", "deactivated", "storage failure"} {
		t.Run(state, func(t *testing.T) {
			withVerificationTestDB(t)
			testutils.WithConfigOverride(t, func() {
				config.Values.SmtpHost = ""
				config.Bootstrap.AntiTimingMinMs = 10
				config.Bootstrap.AntiTimingMaxMs = 11
			})
			var id string
			if state != "unknown" {
				usr, err := user.CreateUser("resend-probe", "Password123!", "resend@example.com")
				require.NoError(t, err)
				id = usr.ID
				var query string
				switch state {
				case "verified":
					query = "UPDATE users SET is_email_verified=TRUE WHERE id=?"
				case "no email":
					query = "UPDATE users SET email='' WHERE id=?"
				case "deactivated":
					query = "UPDATE users SET deactivated_at=CURRENT_TIMESTAMP WHERE id=?"
				case "storage failure":
					query = "CREATE TRIGGER fail_resend BEFORE UPDATE OF email_verification_token ON users BEGIN SELECT RAISE(ABORT,'injected failure'); END"
				}
				if query != "" {
					var err error
					if state == "storage failure" {
						_, err = db.GetDB().Exec(query)
					} else {
						_, err = db.GetDB().Exec(query, id)
					}
					require.NoError(t, err)
				}
			}
			rr := httptest.NewRecorder()
			started := time.Now()
			HandleResendVerification(rr, privacyResendRequest())
			require.GreaterOrEqual(t, time.Since(started), 10*time.Millisecond, "all account states must use the same delay policy")
			require.Equal(t, http.StatusOK, rr.Code)
			require.Empty(t, rr.Header().Get("Location"))
			require.NotContains(t, rr.Body.String(), "already verified")
			require.NotContains(t, rr.Body.String(), "Something went wrong")
			if state == "unknown" {
				generic = rr.Body.String()
			} else {
				require.Equal(t, generic, rr.Body.String())
			}
			if state == "unverified" {
				var hash string
				var expiry time.Time
				require.NoError(t, db.GetDB().QueryRow("SELECT email_verification_token,email_verification_expires_at FROM users WHERE id=?", id).Scan(&hash, &expiry))
				require.NotEmpty(t, hash)
				require.True(t, expiry.After(time.Now()))
			}
		})
	}
}

func TestResendReturnsWhileDeliveryIsBlockedAndLinkStillWorks(t *testing.T) {
	withVerificationTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.SmtpHost = "smtp.example.test"
		config.Bootstrap.AntiTimingMinMs = 0
		config.Bootstrap.AntiTimingMaxMs = 0
	})
	usr, err := user.CreateUser("resend-probe", "Password123!", "resend@example.com")
	require.NoError(t, err)
	type delivery struct{ to, link string }
	started := make(chan delivery, 1)
	release := make(chan struct{})
	senderDone := make(chan struct{})
	response := make(chan *httptest.ResponseRecorder, 1)
	var unblock sync.Once
	cleanup := func() { unblock.Do(func() { close(release) }) }
	t.Cleanup(cleanup)
	go func() {
		rr := httptest.NewRecorder()
		handleResendVerification(rr, privacyResendRequest(), func(to, link string) error {
			defer close(senderDone)
			started <- delivery{to, link}
			<-release
			return nil
		})
		response <- rr
	}()
	var mail delivery
	select {
	case mail = <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("verification sender did not start")
	}
	// Cleanup waits for the blocked sender before restoring configuration or DB.
	t.Cleanup(func() {
		cleanup()
		select {
		case <-senderDone:
		case <-time.After(5 * time.Second):
			t.Error("sender did not stop")
		}
	})
	select {
	case rr := <-response:
		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), "Check your inbox")
		require.NotContains(t, rr.Body.String(), "already verified")
	case <-time.After(time.Second):
		t.Fatal("SMTP blocked the public response")
	}
	require.Equal(t, "resend@example.com", mail.to)
	parsed, err := url.Parse(mail.link)
	require.NoError(t, err)
	require.NotEmpty(t, parsed.Query().Get("token"))
	require.NotEmpty(t, parsed.Query().Get("authorize_sig"))
	cleanup()
	<-senderDone
	// A real signed verification link was stored before asynchronous delivery.
	rr := httptest.NewRecorder()
	HandleVerifyEmail(rr, httptest.NewRequest(http.MethodGet, mail.link, nil))
	require.Equal(t, http.StatusFound, rr.Code)
	require.Contains(t, rr.Header().Get("Location"), "http://localhost/callback")
	current, err := user.UserByID(usr.ID)
	require.NoError(t, err)
	require.True(t, current.IsEmailVerified)
}
